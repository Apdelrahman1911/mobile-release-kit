//! Closed profile phases of the existing Apple provisioning protocol.
//! Public metadata and native comparison replies are DATA, never a restored
//! key loan, distribution trust result, save permission or finality receipt.
use super::*;
use crate::{
    apple_provisioning_journal::{
        profile_choice_valid, profile_entitlements_sha256, profile_identity_sha256,
        profile_unix_micros, NativeSettlement, ProfileAction, ProfileBundle, ProfileCertificate,
        ProfileDownload, ProfileJournalAck, ProfileProvider, ProfileSaveState, ProfileSelection,
        ProfileSetupIntent, ProfileSetupRow, ProfileTarget, ProfileUpdate,
    },
    credential_setup::KeyReference,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const PROFILE_EVENTS: u32 = 4;
pub(crate) const PROFILE_IDENTITY_LIMIT: usize = 128 * 1024;
pub(crate) const PROFILE_JSON_LIMIT: usize = 256 * 1024;
pub(crate) const PROFILE_DER_LIMIT: usize = 64 * 1024;
pub(crate) const PROFILE_SPKI_LIMIT: usize = 16 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileChoice {
    pub(crate) action: ProfileAction,
    pub(crate) bundle: ProfileBundle,
    pub(crate) certificate: ProfileCertificate,
    #[serde(deserialize_with = "required_option")]
    pub(crate) profile: Option<ProfileSelection>,
    pub(crate) plan_sha256: String,
    #[serde(deserialize_with = "required_option")]
    pub(crate) request_body_sha256: Option<String>,
}
impl ProfileChoice {
    fn valid(&self, target: &ProfileTarget, at: &str) -> bool {
        sha(&self.plan_sha256)
            && profile_choice_valid(
                target,
                &self.bundle,
                &self.certificate,
                self.profile.as_ref(),
                at,
            )
            && match self.action {
                ProfileAction::ReuseDownload => {
                    self.profile.is_some() && self.request_body_sha256.is_none()
                }
                ProfileAction::CreateProfile => {
                    self.profile.is_none()
                        && self
                            .request_body_sha256
                            .as_ref()
                            .is_some_and(|value| sha(value))
                }
            }
    }
    pub(crate) fn same_assets(&self, other: &Self) -> bool {
        // A fresh Start has a different operation-derived profile name and
        // plan hash. It still must select the exact originally reviewed assets.
        self.action == other.action
            && self.bundle == other.bundle
            && self.certificate == other.certificate
            && self.profile == other.profile
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfileReviewData {
    pub(crate) reference: Reference,
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) selection: ProfileChoice,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfilePriorData {
    pub(crate) reference: Reference,
    pub(crate) source_key: KeyReference,
    pub(crate) target: ProfileTarget,
    pub(crate) profile_resource_id: Option<String>,
    pub(crate) profile_name: String,
    pub(crate) profile_sha256: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfileScopeData {
    pub(crate) source_key: KeyReference,
    pub(crate) destination: Option<KeyReference>,
    pub(crate) expected_certificate_sha256: String,
    pub(crate) p12_sha256: String,
    pub(crate) entitlements: Value,
    pub(crate) review: Option<ProfileReviewData>,
    pub(crate) prior: Option<ProfilePriorData>,
}
impl ProfileScopeData {
    pub(crate) fn target(&self, bundle: &BundleTarget) -> Result<ProfileTarget, BridgeError> {
        Ok(ProfileTarget {
            bundle_id: bundle.bundle_id.clone(),
            team_id: bundle.team_id.clone(),
            app_id_prefix: bundle.app_id_prefix.clone(),
            display_name: bundle.display_name.clone(),
            existing_application: bundle.existing_application,
            entitlements_sha256: profile_entitlements_sha256(&self.entitlements)
                .map_err(|_| invalid())?,
        })
    }
    pub(super) fn valid(
        &self,
        context: &Context,
        bundle: &BundleTarget,
        reviewed: Option<&String>,
    ) -> bool {
        let Ok(target) = self.target(bundle) else {
            return false;
        };
        if !context.mode.profile()
            || self.source_key.validate().is_err()
            || context.p12_record_id.as_deref() != Some(self.source_key.record_id.as_str())
            || context.p12_record_revision != Some(self.source_key.revision_counter)
            || !sha(&self.expected_certificate_sha256)
            || !sha(&self.p12_sha256)
            || bundle.team_id != bundle.app_id_prefix
        {
            return false;
        }
        if context.mode.profile_save() {
            let (Some(destination), Some(review)) = (&self.destination, &self.review) else {
                return false;
            };
            if destination.validate().is_err()
                || destination.vault_id != self.source_key.vault_id
                || destination.generation_id != self.source_key.generation_id
                || destination.record_id == self.source_key.record_id
                || destination.revision_id == self.source_key.revision_id
                || destination.revision_counter != 1
                || context.reference.as_ref() != Some(&review.reference)
                || reviewed != Some(&review.observed_at)
                || !interval(&review.observed_at, &review.valid_until)
                || !review.selection.valid(&target, &review.observed_at)
                || (review.selection.action == ProfileAction::ReuseDownload)
                    != (context.mode == Mode::ProfileReuse)
            {
                return false;
            }
        } else if self.destination.is_some() || self.review.is_some() || reviewed.is_some() {
            return false;
        }
        match (&self.prior, context.mode) {
            (Some(prior), Mode::ProfileReconcile) => {
                prior.source_key == self.source_key
                    && prior.target == target
                    && context.reference.as_ref() == Some(&prior.reference)
                    && display_name(&prior.profile_name)
                    && prior
                        .profile_resource_id
                        .as_ref()
                        .is_none_or(|id| resource_id(id))
                    && prior
                        .profile_sha256
                        .as_ref()
                        .is_none_or(|digest| sha(digest))
            }
            (None, mode) => mode != Mode::ProfileReconcile,
            _ => false,
        }
    }
}

fn interval(before: &str, after: &str) -> bool {
    profile_unix_micros(before)
        .zip(profile_unix_micros(after))
        .is_some_and(|(before, after)| after.checked_sub(before) == Some(300_000_000))
}

/// A prior row is historical comparison only. It cannot reopen its original
/// reservation/destination, erase Pending, authorize a POST or write its row.
pub(crate) fn profile_recovery_scope_matches(row: &ProfileSetupRow, scope: &ScopeData) -> bool {
    let Some(signing) = &scope.signing else {
        return false;
    };
    let Ok(target) = signing.target(&scope.target) else {
        return false;
    };
    row.intent.context.account_ref == scope.provisioning.account_ref
        && row.intent.provenance.project_binding == scope.provenance.project_binding
        && row.intent.provenance.registered_root == scope.provenance.registered_root
        && row.intent.source_key == signing.source_key
        && row.intent.target == target
}
pub(crate) fn profile_prior(
    account: &AccountSnapshot,
    scope: &ScopeData,
    context: &Context,
) -> Result<Option<ProfilePriorData>, BridgeError> {
    if context.mode != Mode::ProfileReconcile {
        return Ok(None);
    }
    let reference = context.reference.as_ref().ok_or_else(invalid)?;
    let mut rows = account.profile_rows.iter().filter(|row| {
        row.intent.provenance.operation_id.as_str() == reference.operation_id
            && row.intent.provenance.owner_generation.as_str() == reference.owner_generation
    });
    let row = rows.next().ok_or_else(invalid)?;
    need(rows.next().is_none() && profile_recovery_scope_matches(row, scope))?;
    let selected = row
        .update
        .download
        .as_ref()
        .map(|value| &value.profile)
        .or(row.intent.profile.as_ref());
    let id =
        selected
            .map(|value| value.resource_id.clone())
            .or_else(|| match &row.update.provider {
                ProfileProvider::Creation(value) => value.response_resource_id.clone(),
                _ => None,
            });
    Ok(Some(ProfilePriorData {
        reference: reference.clone(),
        source_key: row.intent.source_key.clone(),
        target: row.intent.target.clone(),
        profile_resource_id: id,
        profile_name: selected.map_or_else(|| row.intent.profile_name(), |p| p.name.clone()),
        profile_sha256: row.update.download.as_ref().map(|p| p.sha256.clone()),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileIdentity {
    certificate_der: String,
    public_key_spki_der: String,
    chain_sha256: Vec<String>,
    chain_checked_at: String,
    source_key: KeyReference,
    p12_sha256: String,
}
/// Retained public-only phase input. It has no Clone/Debug/Serialize and never
/// leaves the private reader/identity-check path as an event/status object.
pub(crate) struct IdentityInput {
    pub(crate) leaf: Vec<u8>,
    pub(crate) spki: Vec<u8>,
    pub(crate) identity_sha256: String,
    pub(crate) chain_checked_at: u64,
}

pub(super) fn unbase64(value: &str, limit: usize) -> Result<Vec<u8>, BridgeError> {
    let bytes = value.as_bytes();
    need(!bytes.is_empty() && bytes.len() % 4 == 0 && bytes.len() <= (limit + 2) / 3 * 4)?;
    let digit = |b| match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let padding =
        usize::from(bytes[bytes.len() - 1] == b'=') + usize::from(bytes[bytes.len() - 2] == b'=');
    let size = bytes.len() / 4 * 3 - padding;
    need(size > 0 && size <= limit)?;
    let mut output = Vec::new();
    output.try_reserve_exact(size).map_err(|_| invalid())?;
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let a = digit(chunk[0]).ok_or_else(invalid)?;
        let b = digit(chunk[1]).ok_or_else(invalid)?;
        let last = index + 1 == bytes.len() / 4;
        let c = if chunk[2] == b'=' && last && padding == 2 {
            0
        } else {
            digit(chunk[2]).ok_or_else(invalid)?
        };
        let d = if chunk[3] == b'=' && last && padding > 0 {
            0
        } else {
            digit(chunk[3]).ok_or_else(invalid)?
        };
        output.push((a << 2) | (b >> 4));
        if !last || padding < 2 {
            output.push((b << 4) | (c >> 2));
        }
        if !last || padding == 0 {
            output.push((c << 6) | d);
        }
        need(!last || padding != 2 || b & 15 == 0)?;
        need(!last || padding != 1 || c & 3 == 0)?;
    }
    need(output.len() == size)?;
    Ok(output)
}
fn identity(value: Value, binding: &RequestBinding) -> Result<IdentityInput, BridgeError> {
    let selected = binding.scope.signing.as_ref().ok_or_else(invalid)?;
    let digest = profile_identity_sha256(&value).map_err(|_| invalid())?;
    let value = ProfileIdentity::deserialize(value).map_err(|_| invalid())?;
    need(
        value.source_key == selected.source_key
            && value.p12_sha256 == selected.p12_sha256
            && (1..=8).contains(&value.chain_sha256.len())
            && value.chain_sha256.iter().all(|part| sha(part))
            && value
                .chain_sha256
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == value.chain_sha256.len(),
    )?;
    let leaf = unbase64(&value.certificate_der, PROFILE_DER_LIMIT)?;
    let spki = unbase64(&value.public_key_spki_der, PROFILE_SPKI_LIMIT)?;
    need(hex(&Sha256::digest(&leaf)) == selected.expected_certificate_sha256)?;
    Ok(IdentityInput {
        leaf,
        spki,
        identity_sha256: digest,
        chain_checked_at: profile_unix_micros(&value.chain_checked_at).ok_or_else(invalid)?,
    })
}

/// Native syntax/key comparison on the original captured DER. Offline chain
/// verification stays in the same protected worker; ASC DER/type comparison
/// follows this ACK there. This object deliberately is not CertificateBinding.
pub(crate) struct IdentityComparison {
    binding: Arc<RequestBinding>,
    identity_sha256: String,
    certificate_sha256: String,
    public_key_sha256: String,
    not_before: u64,
    not_after: u64,
    checked_at: u64,
}
impl IdentityComparison {
    pub(crate) fn inspect(
        binding: &Arc<RequestBinding>,
        input: &IdentityInput,
        at: SystemTime,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<Self, BridgeError> {
        need(binding.context.mode.profile() && !stop())?;
        let selected = binding.scope.signing.as_ref().ok_or_else(invalid)?;
        let team: [u8; 10] = binding
            .scope
            .target
            .team_id
            .as_bytes()
            .try_into()
            .map_err(|_| invalid())?;
        let spki: [u8; 32] = Sha256::digest(&input.spki).into();
        let micros = at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_micros();
        // Comparison never grants freshness. This only rejects stale/future
        // reports; the original monotonic operation/loan gate is rechecked by
        // the caller before and after this maintained native parser.
        need(
            u128::from(input.chain_checked_at) <= micros
                && micros - u128::from(input.chain_checked_at) <= 300_000_000,
        )?;
        let candidate = crate::credential_format::inspect_certificate_candidate(
            &input.leaf,
            &team,
            &spki,
            at,
            stop,
        )
        .map_err(|_| invalid())?;
        need(
            hex(candidate.certificate_sha256()) == selected.expected_certificate_sha256 && !stop(),
        )?;
        Ok(Self {
            binding: binding.clone(),
            identity_sha256: input.identity_sha256.clone(),
            certificate_sha256: hex(candidate.certificate_sha256()),
            public_key_sha256: hex(candidate.spki_sha256()),
            not_before: candidate.not_before_unix_seconds(),
            not_after: candidate.not_after_unix_seconds(),
            checked_at: u64::try_from(micros / 1_000_000).map_err(|_| invalid())?,
        })
    }
    pub(crate) fn matches(
        &self,
        binding: &Arc<RequestBinding>,
        certificate: &ProfileCertificate,
    ) -> bool {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        let now = now.as_secs();
        // The identity phase does not freeze wall-clock validity for a later
        // Pending ACK. No worker-supplied time can extend this comparison.
        now >= self.not_before
            && now < self.not_after
            && now >= self.checked_at
            && now - self.checked_at <= 300
            && Arc::ptr_eq(&self.binding, binding)
            && certificate.certificate_sha256 == self.certificate_sha256
            && certificate.public_key_sha256 == self.public_key_sha256
            && profile_unix_micros(&certificate.not_before)
                == self.not_before.checked_mul(1_000_000)
            && profile_unix_micros(&certificate.expires_at) == self.not_after.checked_mul(1_000_000)
    }
    pub(crate) fn reply(&self, binding: &Arc<RequestBinding>) -> Result<Vec<u8>, BridgeError> {
        need(Arc::ptr_eq(&self.binding, binding))?;
        reply(
            binding,
            "identity-ack",
            1,
            json!({"identitySha256":self.identity_sha256,
            "certificateSha256":self.certificate_sha256,"publicKeySha256":self.public_key_sha256,
            "teamId":binding.scope.target.team_id,"notBefore":self.not_before,"notAfter":self.not_after,"checkedAt":self.checked_at}),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProfileDecision {
    ReuseAvailable,
    CreateAvailable,
    Blocked,
    DownloadReturned,
    CreationUnconfirmed,
    ComparisonOnly,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProfileReason {
    ReuseExistingProfile,
    ProfileCreateReview,
    IdentityRequired,
    BundleRequired,
    ProfileSelectionRequired,
    InventoryUnavailable,
    InventoryIncomplete,
    PendingSetup,
    CapabilitiesManual,
    SelectionChanged,
    ProfileReturned,
    ProviderUnconfirmed,
    SameResponse,
    Unattributed,
    NotReturned,
    Inconclusive,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileObserved {
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) before_sha256: String,
    pub(crate) available: bool,
    pub(crate) relationships_complete: bool,
    pub(crate) decision: ProfileDecision,
    pub(crate) reason: ProfileReason,
    #[serde(deserialize_with = "required_option")]
    pub(crate) selection: Option<ProfileChoice>,
}
impl ProfileObserved {
    fn valid(&self, binding: &RequestBinding) -> bool {
        let Some(scope) = &binding.scope.signing else {
            return false;
        };
        let Ok(target) = scope.target(&binding.scope.target) else {
            return false;
        };
        if !interval(&self.observed_at, &self.valid_until)
            || !sha(&self.before_sha256)
            || self
                .selection
                .as_ref()
                .is_some_and(|choice| !self.available || !choice.valid(&target, &self.observed_at))
        {
            return false;
        }
        match (binding.context.mode, self.decision) {
            (Mode::ProfileReview, ProfileDecision::ReuseAvailable) => {
                self.reason == ProfileReason::ReuseExistingProfile
                    && self
                        .selection
                        .as_ref()
                        .is_some_and(|s| s.action == ProfileAction::ReuseDownload)
            }
            (Mode::ProfileReview, ProfileDecision::CreateAvailable) => {
                self.relationships_complete
                    && self.reason == ProfileReason::ProfileCreateReview
                    && self
                        .selection
                        .as_ref()
                        .is_some_and(|s| s.action == ProfileAction::CreateProfile)
            }
            (Mode::ProfileReview, ProfileDecision::Blocked) => {
                self.selection.is_none()
                    && matches!(
                        self.reason,
                        ProfileReason::IdentityRequired
                            | ProfileReason::BundleRequired
                            | ProfileReason::ProfileSelectionRequired
                            | ProfileReason::InventoryUnavailable
                            | ProfileReason::InventoryIncomplete
                            | ProfileReason::PendingSetup
                            | ProfileReason::CapabilitiesManual
                            | ProfileReason::SelectionChanged
                    )
            }
            (Mode::ProfileReconcile, ProfileDecision::ComparisonOnly) => {
                self.selection.is_none()
                    && matches!(
                        self.reason,
                        ProfileReason::SameResponse
                            | ProfileReason::Unattributed
                            | ProfileReason::NotReturned
                            | ProfileReason::Inconclusive
                    )
            }
            _ => false,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    observed_at: String,
    valid_until: String,
    before_sha256: String,
    selection: ProfileChoice,
    update: ProfileUpdate,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Updated {
    update: ProfileUpdate,
}
pub(crate) enum ProfileEvent {
    Identity(IdentityInput),
    Observed(ProfileObserved),
    Pending {
        intent: ProfileSetupIntent,
        update: ProfileUpdate,
    },
    Attempt(ProfileUpdate),
}
#[derive(Default)]
pub(super) struct ProfileDecoder {
    identity: bool,
    pub(super) observed: Option<ProfileObserved>,
    pub(super) intent: Option<ProfileSetupIntent>,
    pub(super) update: Option<ProfileUpdate>,
}
impl ProfileDecoder {
    pub(super) fn event(
        &mut self,
        binding: &RequestBinding,
        step: u32,
        kind: &str,
        value: Value,
    ) -> Result<ProfileEvent, BridgeError> {
        need(binding.context.mode.profile() && (1..=PROFILE_EVENTS).contains(&step))?;
        if step == 1 {
            need(kind == "identity" && !self.identity)?;
            let input = identity(value, binding)?;
            self.identity = true;
            return Ok(ProfileEvent::Identity(input));
        }
        need(self.identity)?;
        if !binding.context.mode.profile_save() {
            need(step == 2 && kind == "profile-observed" && self.observed.is_none())?;
            let observed = ProfileObserved::deserialize(value).map_err(|_| invalid())?;
            need(observed.valid(binding))?;
            self.observed = Some(observed.clone());
            return Ok(ProfileEvent::Observed(observed));
        }
        if step == 2 {
            need(kind == "profile-pending" && self.intent.is_none())?;
            let pending = Pending::deserialize(value).map_err(|_| invalid())?;
            let scope = binding.scope.signing.as_ref().ok_or_else(invalid)?;
            let review = scope.review.as_ref().ok_or_else(invalid)?;
            need(
                pending.selection.same_assets(&review.selection)
                    && pending.update.sequence == 1
                    && pending.update.save == ProfileSaveState::NotEntered
                    && pending.update.saved_reference.is_none()
                    && pending.update.download.is_none()
                    && !pending.update.cancel_requested,
            )?;
            let intent = ProfileSetupIntent {
                context: binding.scope.provisioning.clone(),
                provenance: binding.scope.provenance.clone(),
                target: scope.target(&binding.scope.target)?,
                action: pending.selection.action,
                source_key: scope.source_key.clone(),
                destination: scope.destination.as_ref().ok_or_else(invalid)?.clone(),
                bundle: pending.selection.bundle,
                certificate: pending.selection.certificate,
                profile: pending.selection.profile,
                observed_at: pending.observed_at,
                valid_until: pending.valid_until,
                before_sha256: pending.before_sha256,
                plan_sha256: pending.selection.plan_sha256,
                request_body_sha256: pending.selection.request_body_sha256,
            };
            intent.validate().map_err(|_| invalid())?;
            pending.update.validate(&intent).map_err(|_| invalid())?;
            match (&pending.update.provider, binding.context.mode) {
                (ProfileProvider::DownloadPending, Mode::ProfileReuse) => (),
                (ProfileProvider::Creation(record), Mode::ProfileCreate) => need(
                    record.status == AttemptStatus::Running
                        && record.reason == AttemptReason::ReadbackRequired
                        && record.possible_send
                        && !record.cancel_requested
                        && record.response_resource_id.is_none()
                        && record.observed_resource_id.is_none(),
                )?,
                _ => return Err(invalid()),
            }
            self.intent = Some(intent.clone());
            self.update = Some(pending.update.clone());
            return Ok(ProfileEvent::Pending {
                intent,
                update: pending.update,
            });
        }
        need(kind == "profile-attempt")?;
        let update = Updated::deserialize(value).map_err(|_| invalid())?.update;
        need(
            update.sequence == step - 1
                && update.save == ProfileSaveState::NotEntered
                && update.saved_reference.is_none(),
        )?;
        update
            .validate(self.intent.as_ref().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        // Exact transition and durable sequence are rechecked by the original
        // journal CAS before ACK; the decoder cannot settle the operation.
        self.update = Some(update.clone());
        Ok(ProfileEvent::Attempt(update))
    }
    pub(super) fn valid_terminal(&self, result: &ProfileResult, binding: &RequestBinding) -> bool {
        if !self.identity || !result.valid(binding) {
            return false;
        }
        if binding.context.mode.profile_save() {
            if result.decision == ProfileDecision::DownloadReturned {
                return self.update.as_ref().is_some_and(|update| {
                    !update.cancel_requested
                        && update
                            .download
                            .as_ref()
                            .is_some_and(|download| result.matches_download(download))
                });
            }
            return result.decision == ProfileDecision::Blocked && self.update.is_none()
                || result.decision == ProfileDecision::CreationUnconfirmed
                    && self.update.is_some();
        }
        self.observed.as_ref().is_some_and(|observed| {
            result.decision == observed.decision && result.reason == observed.reason
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ProfileLimitation {
    ExistingP12Only,
    NoKeyOrCertificateCreation,
    NoBuildOrStoreRelease,
    ProfileScopedOfflineValidation,
    NewVaultRecordNotAssigned,
    NoPostRetry,
    NativeSaveAndJoinsRequired,
}
const LIMITATIONS: [ProfileLimitation; 7] = [
    ProfileLimitation::ExistingP12Only,
    ProfileLimitation::NoKeyOrCertificateCreation,
    ProfileLimitation::NoBuildOrStoreRelease,
    ProfileLimitation::ProfileScopedOfflineValidation,
    ProfileLimitation::NewVaultRecordNotAssigned,
    ProfileLimitation::NoPostRetry,
    ProfileLimitation::NativeSaveAndJoinsRequired,
];
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProfileResult {
    schema_version: u32,
    scope: String,
    mode: Mode,
    pub(crate) decision: ProfileDecision,
    pub(crate) reason: ProfileReason,
    bundle_id: String,
    #[serde(deserialize_with = "required_option")]
    profile_resource_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    profile_uuid: Option<String>,
    saved: bool,
    credential_ready: bool,
    cancellation_requested: bool,
    limitations: Vec<ProfileLimitation>,
}
impl ProfileResult {
    fn valid(&self, binding: &RequestBinding) -> bool {
        if self.schema_version != 1
            || self.scope != "local-ios-profile-setup"
            || self.mode != binding.context.mode
            || !self.mode.profile()
            || self.bundle_id != binding.scope.target.bundle_id
            || self.saved
            || self.credential_ready
            || self.limitations.as_slice() != LIMITATIONS
            || self.profile_resource_id.is_some() != self.profile_uuid.is_some()
            || self
                .profile_resource_id
                .as_ref()
                .is_some_and(|id| !resource_id(id))
            || self.profile_uuid.as_ref().is_some_and(|value| {
                value.len() != 36
                    || !value.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_digit() || (b'A'..=b'F').contains(&b)
                        }
                    })
            })
        {
            return false;
        }
        match self.decision {
            ProfileDecision::ReuseAvailable => {
                self.mode == Mode::ProfileReview
                    && self.reason == ProfileReason::ReuseExistingProfile
            }
            ProfileDecision::CreateAvailable => {
                self.mode == Mode::ProfileReview
                    && self.reason == ProfileReason::ProfileCreateReview
            }
            ProfileDecision::DownloadReturned => {
                self.mode.profile_save()
                    && self.reason == ProfileReason::ProfileReturned
                    && self.profile_resource_id.is_some()
                    && !self.cancellation_requested
            }
            ProfileDecision::CreationUnconfirmed => {
                self.mode == Mode::ProfileCreate
                    && self.reason == ProfileReason::ProviderUnconfirmed
            }
            ProfileDecision::ComparisonOnly => self.mode == Mode::ProfileReconcile,
            ProfileDecision::Blocked => !self.mode.eq(&Mode::ProfileReconcile),
        }
    }
    pub(crate) fn matches_download(&self, download: &ProfileDownload) -> bool {
        self.profile_resource_id.as_ref() == Some(&download.profile.resource_id)
            && self.profile_uuid.as_ref() == Some(&download.profile.uuid)
    }
}

fn reply(
    binding: &RequestBinding,
    kind: &str,
    step: u32,
    payload: Value,
) -> Result<Vec<u8>, BridgeError> {
    let value = json!({"protocol":PROTOCOL,"operationId":binding.operation,"ownerGeneration":binding.generation,
        "nonce":binding.nonce,"requestSha256":binding.sha256,"kind":kind,"step":step,"payload":payload});
    let mut bytes = bounded(&value, ACK_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n');
    Ok(bytes)
}
pub(crate) fn profile_journal_ack(
    binding: &RequestBinding,
    ack: &ProfileJournalAck,
    expected: &ProfileUpdate,
    previous: crate::application_state_store::Revision,
) -> Result<Vec<u8>, BridgeError> {
    let scope = binding.scope.signing.as_ref().ok_or_else(invalid)?;
    need(
        binding.context.mode.profile_save()
            && (1..PROFILE_EVENTS).contains(&expected.sequence)
            && ack.revision.0 == previous.0.checked_add(1).ok_or_else(invalid)?
            && ack.row.intent.context == binding.scope.provisioning
            && ack.row.intent.provenance == binding.scope.provenance
            && ack.row.intent.target == scope.target(&binding.scope.target)?
            && ack.row.intent.source_key == scope.source_key
            && scope.destination.as_ref() == Some(&ack.row.intent.destination)
            && ack.original.intent() == &ack.row.intent
            && &ack.row.update == expected
            && ack.row.native_settlement == NativeSettlement::Pending,
    )?;
    reply(
        binding,
        "journal-ack",
        expected.sequence + 1,
        json!({"revision":ack.revision.0,"sequence":expected.sequence,
        "recordSha256":expected.sha256().map_err(|_| invalid())?}),
    )
}
