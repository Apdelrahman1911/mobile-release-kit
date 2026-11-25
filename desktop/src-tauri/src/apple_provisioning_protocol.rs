//! Closed Bundle-ID provisioning DATA for the original SavedCommand owner.
//! Neither this decoder nor a journal ACK establishes native currentness,
//! consent, durable job completion, account membership or signing readiness.
use std::{path::Path, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    android_build_protocol::{Content, SavedVersion},
    apple_provisioning_journal::{
        AccountSnapshot, Action, AttemptReason, AttemptStatus, AttemptUpdate,
        BundleRegistrationIntent, BundleTarget, JournalAck, JournalRow, NativeProvenance,
        ProvisioningContext, ROWS,
    },
    asset_source::RegisteredRoot,
    edit_protocol::{bounded, token},
    error::BridgeError,
    protocol::{strict_json, valid_id},
    service_protocol::{hex, Id},
};

// Vocabulary reuse is DATA only. The Access context, consent and operation
// cannot enter this separately selected provisioning domain.
pub(crate) use crate::local_store_preflight_protocol::{
    Availability, ExecutionMode, Outcome, Phase, Profile,
};

#[path = "apple_provisioning_recovery_selection.rs"]
mod recovery_selection;
#[path = "apple_provisioning_profile_recovery_selection.rs"]
mod profile_recovery_selection;
pub(crate) use profile_recovery_selection::{profile_recovery_history, ProfileRecoveryHistory, PROFILE_RECOVERY_LIMIT};
pub(crate) use recovery_selection::{
    recovery_history, recovery_scope_matches, RecoveryHistory, RECOVERY_LIMIT,
};
#[cfg(test)]
pub(crate) use recovery_selection::tests::sample as recovery_comparison_fixture;

#[path = "apple_provisioning_profile_protocol.rs"]
mod profile;
pub(crate) use profile::{ProfileScopeData, ProfileReviewData, ProfilePriorData, ProfileChoice,
    ProfileObserved, ProfileEvent, ProfileResult, ProfileDecision, ProfileReason,
    IdentityInput, IdentityComparison, profile_journal_ack, profile_prior, profile_recovery_scope_matches,
    PROFILE_EVENTS, PROFILE_IDENTITY_LIMIT, PROFILE_JSON_LIMIT};

#[path = "apple_provisioning_key_protocol.rs"]
mod key;
pub(crate) use key::{KeyScopeData, KeyReviewData, KeyReviewChoice, KeyVaultInventory,
    KeyObserved, KeyEvent, KeyNotGenerated, KeyResult, KeyDecision, KeyReason,
    key_pending_ack, key_retained_ack, KEY_EVENTS, KEY_JSON_LIMIT, KEY_STOP};

#[path = "apple_provisioning_key_recovery_protocol.rs"]
mod key_recovery;
pub(crate) use key_recovery::{KeyRecoveryStamp, KeyRecoverySelection, KeyRecoveryInput,
    key_recovery_selection, key_recovery_record, key_recovery_ack, key_recovery_relations};
use key_recovery::key_recovery_input;

#[path = "apple_provisioning_certificate_protocol.rs"]
mod certificate;
#[path = "apple_provisioning_certificate_recovery_selection.rs"]
mod certificate_recovery;
pub(crate) use certificate_recovery::{CertificateRecoveryHistory, CertificateRecoveryAttempt, certificate_recovery_history, certificate_recovery_scope_matches, certificate_prior, certificate_key_preparation, CERTIFICATE_RECOVERY_LIMIT};
pub(crate) use certificate::{CertificateChoice, CertificateReviewData, CertificateKeyPreparation, CertificateRecoveredKey,
    CertificatePriorData, CertificateScopeData, CertificateKeyInput, CertificateCandidateInput,
    CertificateIdentityInput, CertificatePolicyInput, CertificateObserved, CertificateEvent, CertificateResult,
    certificate_reply, certificate_journal_ack, CERTIFICATE_EVENTS, CERTIFICATE_IDENTITY_LIMIT,
    CERTIFICATE_IDENTITIES_LIMIT, CERTIFICATE_JSON_LIMIT, CERTIFICATE_BATCH_DER};

#[path = "apple_provisioning_p12_protocol.rs"]
mod p12;
pub(crate) use p12::{P12Choice,P12ReviewData,P12HistoryHint,P12ScopeData,P12Decision,P12Reason,
    P12Observed,P12ReuseComparison,P12Result,P12Event,p12_journal_ack,p12_custody_ack,P12_EVENTS,P12_COMMANDS};

pub(crate) const PROTOCOL: &str = "mrk-apple-bundle-provisioning/1";
pub(crate) const EVENT: &str = "apple-bundle-provisioning-state-changed";
pub(crate) const IPC_LIMIT: usize = 8192;
pub(crate) const REQUEST_LIMIT: usize = 64 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 128 * 1024;
pub(crate) const EVENT_LIMIT: usize = 16 * 1024;
pub(crate) const FRAME_LIMIT: usize = 32 * 1024;
pub(crate) const ACK_LIMIT: usize = 2048;
// The bounded native historical list is not part of any worker frame.
pub(crate) const STATUS_LIMIT: usize = 64 * 1024;
pub(crate) const MAX_EVENTS: u32 = 3;

pub(crate) fn invalid() -> BridgeError {
    BridgeError::new(
        "apple_provisioning_invalid",
        "The Bundle-ID provisioning request is invalid.",
    )
}
fn need(value: bool) -> Result<(), BridgeError> {
    if value {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == names.len() && names.iter().all(|name| object.contains_key(*name))
    })
}
fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn resource_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}
fn display_name(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= 128
        && !value.chars().any(|ch| ch < '\u{20}' || ch == '\u{7f}')
}
fn bundle_id(value: &str) -> bool {
    value.len() <= 255
        && value.split('.').count() >= 2
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
fn team(value: &str) -> bool {
    value.len() == 10
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    decoder: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(decoder)
}

// Timestamp framing only. The same trusted core validates Gregorian UTC;
// Service revalidates the full timestamp/300s interval and all hashes before
// Pending. Native review expiry is the ORIGINAL monotonic event deadline,
// never this string or the later terminal/GUI observation time.
fn timestamp_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !value.is_ascii() || ![25, 32].contains(&bytes.len()) || !value.ends_with("+00:00") {
        return false;
    }
    bytes[..19].iter().enumerate().all(|(i, byte)| match i {
        4 | 7 => *byte == b'-',
        10 => *byte == b'T',
        13 | 16 => *byte == b':',
        _ => byte.is_ascii_digit(),
    }) && (bytes.len() == 25
        || bytes[19] == b'.'
            && bytes[20..26].iter().all(u8::is_ascii_digit)
            && bytes[20..26].iter().any(|byte| *byte != b'0'))
}
fn native_path(path: &Path) -> Option<&str> {
    let value = path.to_str()?;
    if value.is_empty()
        || value.len() > 3500
        || !value.starts_with('/')
        || value.ends_with('/')
        || value
            .chars()
            .any(|ch| ch.is_control() || ch == ':' || ch == '\\')
    {
        return None;
    }
    let parts: Vec<_> = value[1..].split('/').collect();
    if parts.len() > 128
        || parts
            .iter()
            .any(|part| part.is_empty() || part.len() > 255 || *part == "." || *part == "..")
    {
        return None;
    }
    Some(value)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mode {
    Review,
    Register,
    Reconcile,
    #[serde(rename = "profile-review")]
    ProfileReview,
    #[serde(rename = "profile-reuse")]
    ProfileReuse,
    #[serde(rename = "profile-create")]
    ProfileCreate,
    #[serde(rename = "profile-reconcile")]
    ProfileReconcile,
    #[serde(rename = "key-review")]
    KeyReview,
    #[serde(rename = "key-prepare")]
    KeyPrepare,
    #[serde(rename = "key-recover")]
    KeyRecover,
    #[serde(rename = "certificate-review")]
    CertificateReview,
    #[serde(rename = "certificate-create")]
    CertificateCreate,
    #[serde(rename = "certificate-reconcile")]
    CertificateReconcile,
    #[serde(rename="p12-review")] P12Review,
    #[serde(rename="p12-reuse")] P12Reuse,
    #[serde(rename="p12-save")] P12Save,
}
impl Mode {
    pub(crate) fn key(self) -> bool {
        matches!(self, Self::KeyReview | Self::KeyPrepare | Self::KeyRecover | Self::CertificateReview | Self::CertificateCreate | Self::CertificateReconcile | Self::P12Review | Self::P12Reuse | Self::P12Save)
    }
    pub(crate) fn certificate(self) -> bool { matches!(self, Self::CertificateReview | Self::CertificateCreate | Self::CertificateReconcile) }
    pub(crate) fn p12(self)->bool { matches!(self,Self::P12Review|Self::P12Reuse|Self::P12Save) }
    pub(crate) fn local_key(self) -> bool { matches!(self, Self::KeyReview | Self::KeyPrepare) }
    pub(crate) fn profile(self) -> bool {
        matches!(self, Self::ProfileReview | Self::ProfileReuse | Self::ProfileCreate | Self::ProfileReconcile)
    }
    pub(crate) fn profile_save(self) -> bool { matches!(self, Self::ProfileReuse | Self::ProfileCreate) }
    pub(crate) fn events(self) -> u32 { if self.p12() { P12_EVENTS } else if self.certificate() { CERTIFICATE_EVENTS } else if self.key() { KEY_EVENTS } else if self.profile() { PROFILE_EVENTS } else { MAX_EVENTS } }
    pub(crate) fn frame_limit(self) -> usize { if self.certificate() || self.p12() { CERTIFICATE_IDENTITY_LIMIT } else if self.key() { EVENT_LIMIT } else if self.profile() { PROFILE_IDENTITY_LIMIT } else { FRAME_LIMIT } }
    pub(crate) fn response_limit(self) -> usize { if self.certificate() || self.p12() { CERTIFICATE_JSON_LIMIT } else if self.key() { KEY_JSON_LIMIT } else if self.profile() { PROFILE_JSON_LIMIT } else { RESPONSE_LIMIT } }
    pub(crate) fn consent(self) -> &'static str {
        match self {
            Self::Review => "local-ios-bundle-review-v1",
            Self::Register => "local-ios-bundle-register-v1",
            Self::Reconcile => "local-ios-bundle-reconcile-v1",
            Self::ProfileReview => "local-ios-profile-review-v1",
            Self::ProfileReuse => "local-ios-profile-reuse-v1",
            Self::ProfileCreate => "local-ios-profile-create-v1",
            Self::ProfileReconcile => "local-ios-profile-reconcile-v1",
            Self::KeyReview => "local-ios-key-review-v1",
            Self::KeyPrepare => "local-ios-key-prepare-v1",
            Self::KeyRecover => "local-ios-key-recover-v1",
            Self::CertificateReview => "local-ios-certificate-review-v1",
            Self::CertificateCreate => "local-ios-certificate-create-v1",
            Self::CertificateReconcile => "local-ios-certificate-reconcile-v1",
            Self::P12Review => "local-ios-p12-review-v1",
            Self::P12Reuse => "local-ios-p12-reuse-v1",
            Self::P12Save => "local-ios-p12-save-v1",
        }
    }
    pub(crate) fn commands(self) -> u32 {
        if self.p12() { P12_COMMANDS } else if self.certificate() {
            if self == Self::CertificateCreate { 21 } else { 14 }
        } else if self == Self::KeyReview {
            12
        } else if self.key() {
            7
        } else if self.profile() {
            15
        } else if self == Self::Register {
            9
        } else {
            7
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform {
    Ios,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation {
    AppleBundleProvisioning,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Reference {
    pub(crate) operation_id: String,
    pub(crate) owner_generation: String,
}
impl Reference {
    fn valid(&self) -> bool {
        token(&self.operation_id) && token(&self.owner_generation)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String,
    pub(crate) draft_revision: u32,
    pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content,
    pub(crate) saved_version: SavedVersion,
    pub(crate) credential_context_revision: u32,
    pub(crate) record_id: String,
    pub(crate) record_revision: u32,
    pub(crate) execution_mode: ExecutionMode,
    pub(crate) platform: Platform,
    pub(crate) operation: Operation,
    pub(crate) mode: Mode,
    #[serde(deserialize_with = "required_option")]
    pub(crate) reference: Option<Reference>,
    pub(crate) new_application: bool,
    pub(crate) display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) p12_record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) p12_record_revision: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) key_record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) key_record_revision: Option<u32>,
}
impl Context {
    pub(crate) fn valid(&self) -> bool {
        // KeyRecover is a separate fresh selected-key operation. It never
        // restores an old reservation or enters the generator path.
        valid_id(&self.project_id)
            && self.draft_revision < u32::MAX
            && self.baseline_generation < u32::MAX
            && self.saved_config.valid(524288)
            && self.saved_version.valid()
            && (1..u32::MAX).contains(&self.credential_context_revision)
            && token(&self.record_id)
            && (1..u32::MAX).contains(&self.record_revision)
            && display_name(&self.display_name)
            && self.new_application == (self.mode == Mode::Register)
            && (if matches!(self.mode, Mode::Review | Mode::ProfileReview | Mode::KeyReview | Mode::KeyRecover | Mode::CertificateReview | Mode::P12Review) {
                self.reference.is_none()
            } else {
                self.reference.as_ref().is_some_and(Reference::valid)
            })
            && (if self.mode.certificate() || self.mode.p12() || self.mode == Mode::KeyRecover {
                self.key_record_id.as_ref().is_some_and(|value| token(value))
                    && self.key_record_revision.is_some_and(|value| (1..u32::MAX).contains(&value))
            } else { self.key_record_id.is_none() && self.key_record_revision.is_none() })
            && if self.mode.profile() {
                self.p12_record_id.as_ref().is_some_and(|value| token(value))
                    && self.p12_record_revision.is_some_and(|value| (1..u32::MAX).contains(&value))
            } else if self.mode.p12() {
                match (&self.p12_record_id,self.p12_record_revision) {
                    (Some(id),Some(rev)) => self.mode!=Mode::P12Save && token(id) && (1..u32::MAX).contains(&rev),
                    (None,None) => self.mode!=Mode::P12Reuse,
                    _=>false,
                }
            } else { self.p12_record_id.is_none() && self.p12_record_revision.is_none() }
    }
    pub(crate) fn accepts_target(&self, target: &BundleTarget) -> bool {
        bundle_id(&target.bundle_id)
            && team(&target.team_id)
            && team(&target.app_id_prefix)
            && target.display_name == self.display_name
            && (self.mode != Mode::Register
                || !target.existing_application && target.app_id_prefix == target.team_id)
    }
}
pub(crate) struct Prepare {
    pub(crate) context: Context,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start {
    pub(crate) operation_id: String,
    pub(crate) owner_generation: String,
    consent_version: String,
}
impl Start {
    pub(crate) fn matches_context(&self, context: &Context) -> bool {
        self.consent_version == context.mode.consent()
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel {
    pub(crate) operation_id: String,
    pub(crate) owner_generation: String,
}
pub(crate) fn raw_request(bytes: &[u8]) -> Result<Value, BridgeError> {
    need((1..=IPC_LIMIT).contains(&bytes.len()))?;
    strict_json(bytes).map_err(|_| invalid())
}
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    let profile = value.get("mode").and_then(Value::as_str).is_some_and(|mode|
        matches!(mode, "profile-review" | "profile-reuse" | "profile-create" | "profile-reconcile"));
    let mut names = vec![
            "projectId",
            "draftRevision",
            "baselineGeneration",
            "savedConfig",
            "savedVersion",
            "credentialContextRevision",
            "recordId",
            "recordRevision",
            "executionMode",
            "platform",
            "mode",
            "reference",
            "newApplication",
            "displayName",
        ];
    let p12=value.get("mode").and_then(Value::as_str).is_some_and(|mode|matches!(mode,"p12-review"|"p12-reuse"|"p12-save"));
    if profile || p12 { names.extend(["p12RecordId", "p12RecordRevision"]); }
    if value.get("mode").and_then(Value::as_str).is_some_and(|mode|
        matches!(mode, "certificate-review" | "certificate-create" | "certificate-reconcile" | "key-recover")) || p12 {
        names.extend(["keyRecordId", "keyRecordRevision"]);
    }
    need(keys(value, &names))?;
    let mut selected = value.clone();
    selected.as_object_mut().ok_or_else(invalid)?.insert(
        "operation".into(),
        json!(Operation::AppleBundleProvisioning),
    );
    let context = Context::deserialize(selected).map_err(|_| invalid())?;
    need(context.valid())?;
    Ok(Prepare { context })
}
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    need(keys(
        value,
        &["operationId", "ownerGeneration", "consentVersion"],
    ))?;
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    need(
        token(&input.operation_id)
            && token(&input.owner_generation)
            && [Mode::Review, Mode::Register, Mode::Reconcile, Mode::ProfileReview,
                Mode::ProfileReuse, Mode::ProfileCreate, Mode::ProfileReconcile, Mode::KeyReview, Mode::KeyPrepare, Mode::KeyRecover,
                Mode::CertificateReview, Mode::CertificateCreate, Mode::CertificateReconcile, Mode::P12Review, Mode::P12Reuse, Mode::P12Save]
                .iter()
                .any(|mode| input.consent_version == mode.consent()),
    )?;
    Ok(input)
}
pub(crate) fn cancel(value: &Value) -> Result<Cancel, BridgeError> {
    need(keys(value, &["operationId", "ownerGeneration"]))?;
    let input = Cancel::deserialize(value).map_err(|_| invalid())?;
    need(token(&input.operation_id) && token(&input.owner_generation))?;
    Ok(input)
}
pub(crate) fn status_request(value: &Value) -> Result<(), BridgeError> {
    need(keys(value, &[]))
}

/// Retained comparison data derived by the actual material/Document owner.
/// Public Prepare has neither a target/account override nor these descriptors.
pub(crate) struct ScopeData {
    pub(crate) provisioning: ProvisioningContext,
    pub(crate) provenance: NativeProvenance,
    pub(crate) target: BundleTarget,
    pub(crate) reviewed_at: Option<String>,
    pub(crate) signing: Option<ProfileScopeData>,
    pub(crate) key: Option<KeyScopeData>,
    pub(crate) certificate: Option<CertificateScopeData>,
    pub(crate) p12: Option<P12ScopeData>,
}
impl ScopeData {
    fn matches(
        &self,
        context: &Context,
        operation: &str,
        generation: &str,
        root: &RegisteredRoot,
    ) -> bool {
        let Ok(identity) = root.identity.posix() else {
            return false;
        };
        let identity = identity.preflight_identity();
        let p = &self.provisioning;
        let n = &self.provenance;
        let t = &self.target;
        p.operation_id == operation
            && p.project_id == context.project_id
            && valid_id(&p.client_id)
            && p.observation_revision > 0
            && p.credential_record_id == context.record_id
            && p.credential_revision == context.record_revision
            && p.credential_context_revision == context.credential_context_revision
            && n.operation_id.as_str() == operation
            && n.owner_generation.as_str() == generation
            && n.registration_generation > 0
            && n.draft_revision == context.draft_revision
            && n.baseline_generation == context.baseline_generation
            && n.saved_config == context.saved_config
            && n.saved_version == context.saved_version
            && native_path(&root.path) == Some(n.registered_root.path.as_str())
            && identity.device.parse::<u64>().ok() == Some(n.registered_root.device)
            && identity.inode.parse::<u64>().ok() == Some(n.registered_root.inode)
            && identity.mode == n.registered_root.mode
            && identity.uid == n.registered_root.uid
            && identity.gid == n.registered_root.gid
            && n.project_binding.canonical_root == n.registered_root.path
            && n.project_binding.device == n.registered_root.device
            && n.project_binding.inode == n.registered_root.inode
            && context.accepts_target(t)
            && if context.mode.p12() {
                self.signing.is_none() && self.key.is_none()
                    && self.certificate.as_ref().is_some_and(|scope| scope.valid(context,self))
                    && self.p12.as_ref().is_some_and(|scope| scope.valid(context,self))
            } else if self.p12.is_some() { false
            } else if context.mode.certificate() {
                self.signing.is_none() && self.key.is_none() && self.certificate.as_ref().is_some_and(|scope| scope.valid(context, self))
            } else if self.certificate.is_some() { false
            } else if context.mode.key() {
                self.signing.is_none() && self.key.as_ref().is_some_and(|key| key.valid(context, t, self.reviewed_at.as_ref()))
            } else if context.mode.profile() {
                self.key.is_none() && self.signing.as_ref().is_some_and(|s| s.valid(context, t, self.reviewed_at.as_ref()))
            } else if context.mode == Mode::Register {
                self.key.is_none() && self.signing.is_none() && !t.existing_application
                    && t.team_id == t.app_id_prefix
                    && self
                        .reviewed_at
                        .as_ref()
                        .is_some_and(|value| timestamp_shape(value))
            } else {
                self.key.is_none() && self.signing.is_none() && self.reviewed_at.is_none()
            }
    }
}

/// One original request's nonce/digest/context, not a capability. This is kept
/// private to the native operation and is not serialized as a status.
pub(crate) struct RequestBinding {
    pub(crate) operation: String,
    pub(crate) generation: String,
    pub(crate) context: Context,
    pub(crate) scope: ScopeData,
    nonce: String,
    sha256: String,
    pub(crate) revision: crate::application_state_store::Revision,
}
impl RequestBinding {
    pub(crate) fn certificate_digest(&self) -> &str { &self.sha256 }
}
pub(crate) struct EncodedRequest {
    pub(crate) bytes: Vec<u8>,
    pub(crate) binding: Arc<RequestBinding>,
}

pub(crate) fn request(
    operation: &str,
    generation: &str,
    context: &Context,
    profile: Profile,
    root: &RegisteredRoot,
    cwd: &Path,
    credential_config: &Content,
    work_end_ns: u64,
    hard_end_ns: u64,
    nonce: String,
    mut scope: ScopeData,
    account: &AccountSnapshot,
    prior: Option<&JournalRow>,
) -> Result<EncodedRequest, BridgeError> {
    account.validate_recoveries().map_err(|_| invalid())?;
    if context.mode == Mode::ProfileReconcile {
        let prior = profile_prior(account, &scope, context)?;
        let signing = scope.signing.as_mut().ok_or_else(invalid)?;
        need(signing.prior.is_none())?;
        signing.prior = prior;
    }
    need(
        token(operation)
            && token(generation)
            && context.valid()
            && token(&nonce)
            && credential_config.valid(524288)
            && credential_config == &context.saved_config
            && scope.matches(context, operation, generation, root)
            && account.account == scope.provisioning.account_ref
            && account.rows.len().saturating_add(account.profile_rows.len()).saturating_add(account.key_rows.len()).saturating_add(account.certificate_rows.len()).saturating_add(account.p12_rows.len()).saturating_add(account.key_recoveries.len()) <= ROWS
            // Reserve, up to two attempt writes, then final native CAS. Do not
            // arm a provider write if this fixed whole path can overflow.
            && account.revision.0 <= u64::MAX - if context.mode.profile_save() || matches!(context.mode, Mode::KeyPrepare | Mode::P12Save) { 7 } else { 4 }
            && work_end_ns > 0
            && work_end_ns < hard_end_ns
            && hard_end_ns - work_end_ns <= 10_000_000_000,
    )?;
    let mut seen = std::collections::BTreeSet::new();
    need(account.rows.iter().all(|row| {
        row.intent.context.account_ref == account.account
            && seen.insert(row.intent.context.operation_id.as_str())
    }))?;
    need(account.profile_rows.iter().all(|row| {
        row.intent.context.account_ref == account.account
            && seen.insert(row.intent.context.operation_id.as_str())
    }))?;
    need(account.key_rows.iter().all(|row| row.intent.context.account_ref == account.account
        && seen.insert(row.intent.context.operation_id.as_str())))?;
    need(account.certificate_rows.iter().all(|row| row.intent.context.account_ref == account.account
        && seen.insert(row.intent.context.operation_id.as_str())))?;
    need(account.p12_rows.iter().all(|row| row.intent.context.account_ref == account.account
        && seen.insert(row.intent.context.operation_id.as_str())))?;
    need(account.key_recoveries.iter().all(|row| row.context.account_ref == account.account
        && seen.insert(row.context.operation_id.as_str())))?;
    if context.mode == Mode::Reconcile {
        let reference = context.reference.as_ref().ok_or_else(invalid)?;
        let prior = prior.ok_or_else(invalid)?;
        need(
            account.rows.iter().any(|row| row == prior)
                && prior.intent.provenance.operation_id.as_str() == reference.operation_id
                && prior.intent.provenance.owner_generation.as_str() == reference.owner_generation
                && recovery_scope_matches(prior, &scope)
                && prior.intent.target == scope.target,
        )?;
    } else {
        need(prior.is_none())?;
    }
    let mut pending: Vec<_> = account.rows.iter().map(|row| json!({
        "accountRef":row.intent.context.account_ref,"operationId":row.intent.context.operation_id,
        "action":row.attempt.record.action,"status":row.attempt.record.status,"nativeSettlement":row.native_settlement,
    })).collect();
    // Coarse closed fence only: never expose profile/private references or
    // mistake local-save unknown for a terminal provider disposition.
    pending.extend(account.profile_rows.iter().map(|row| json!({
        "accountRef":row.intent.context.account_ref,"operationId":row.intent.context.operation_id,
        "action":"profile_setup","status":if row.unresolved(){"unknown"}else{"succeeded"},
        "nativeSettlement":row.native_settlement,
    })));
    pending.extend(account.key_rows.iter().map(|row| json!({
        "accountRef":row.intent.context.account_ref,"operationId":row.intent.context.operation_id,
        "action":"key_prepare","status":if row.unresolved(){"unknown"}else{"succeeded"},
        "nativeSettlement":row.native_settlement,
    })));
    pending.extend(account.certificate_rows.iter().map(|row| json!({
        "accountRef":row.intent.context.account_ref,"operationId":row.intent.context.operation_id,
        "action":"create_certificate","status":if row.unresolved(){"unknown"}else{"succeeded"},
        "nativeSettlement":row.native_settlement,
    })));
    pending.extend(account.p12_rows.iter().map(|row| json!({
        "accountRef":row.intent.context.account_ref,"operationId":row.intent.context.operation_id,
        "action":"p12_setup","status":if row.unresolved(){"unknown"}else{"succeeded"},
        "nativeSettlement":row.native_settlement,
    })));
    let identity = root
        .identity
        .posix()
        .map_err(|_| invalid())?
        .preflight_identity();
    let mut value = json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&root.path).ok_or_else(invalid)?,"rootIdentity":identity,
            "cwd":native_path(cwd).ok_or_else(invalid)?,"credentialConfig":credential_config,
            "clock":{"workEndNs":work_end_ns.to_string(),"hardEndNs":hard_end_ns.to_string()},"nonce":nonce,
            "provisioning":scope.provisioning,"target":scope.target,"reviewedAt":scope.reviewed_at,
            "journalRevision":account.revision.0,"pending":pending,"prior":prior}});
    if !account.key_recoveries.is_empty() {
        value["native"].as_object_mut().ok_or_else(invalid)?.insert("keyRecoveries".into(), key_recovery_relations(account)?);
    }
    if context.mode.p12() {
        let data=value["context"].as_object_mut().ok_or_else(invalid)?;
        data.insert("p12RecordId".into(),json!(context.p12_record_id));
        data.insert("p12RecordRevision".into(),json!(context.p12_record_revision));
    }
    if context.mode.profile() {
        value["native"].as_object_mut().ok_or_else(invalid)?
            .insert("signing".into(), serde_json::to_value(&scope.signing).map_err(|_| invalid())?);
    }
    if context.mode.p12() {
        value["native"].as_object_mut().ok_or_else(invalid)?.insert("p12".into(),serde_json::to_value(&scope.p12).map_err(|_| invalid())?);
    }
    if context.mode.certificate() || context.mode.p12() {
        value["native"].as_object_mut().ok_or_else(invalid)?
            .insert("certificate".into(), serde_json::to_value(&scope.certificate).map_err(|_| invalid())?);
    } else if context.mode.key() {
        value["native"].as_object_mut().ok_or_else(invalid)?
            .insert("key".into(), serde_json::to_value(&scope.key).map_err(|_| invalid())?);
    }
    let mut bytes = bounded(&value, REQUEST_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n');
    let binding = Arc::new(RequestBinding {
        operation: operation.into(),
        generation: generation.into(),
        context: context.clone(),
        scope,
        nonce,
        sha256: hex(&Sha256::digest(&bytes)),
        revision: account.revision,
    });
    Ok(EncodedRequest { bytes, binding })
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Observation {
    Found,
    NotReturned,
    NotPermitted,
    Inconclusive,
    NotChecked,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Decision {
    Reuse,
    ReviewRequired,
    Blocked,
    RegistrationUnconfirmed,
    RegistrationConfirmed,
    ComparisonOnly,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BundleMetadata {
    pub(crate) resource_id: String,
    pub(crate) identifier: String,
    pub(crate) platform: String,
    #[serde(deserialize_with = "required_option")]
    pub(crate) seed_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observed {
    pub(crate) observed_at: String,
    pub(crate) observation: Observation,
    #[serde(deserialize_with = "required_option")]
    pub(crate) bundle: Option<BundleMetadata>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) before_sha256: Option<String>,
    pub(crate) decision: Decision,
}
impl Observed {
    fn valid(&self, binding: &RequestBinding) -> bool {
        let readable = matches!(
            self.observation,
            Observation::Found | Observation::NotReturned
        );
        timestamp_shape(&self.observed_at)
            && self.bundle.is_some() == (self.observation == Observation::Found)
            && if readable {
                self.before_sha256.as_ref().is_some_and(|value| sha(value))
            } else {
                self.before_sha256.is_none()
            }
            && self.bundle.as_ref().is_none_or(|bundle| {
                resource_id(&bundle.resource_id)
                    && bundle.identifier == binding.scope.target.bundle_id
                    && matches!(bundle.platform.as_str(), "IOS" | "UNIVERSAL")
                    && bundle.seed_id.as_ref().is_none_or(|value| team(value))
            })
            && match binding.context.mode {
                Mode::Review => match self.decision {
                    Decision::Reuse => self.observation == Observation::Found,
                    Decision::ReviewRequired => self.observation == Observation::NotReturned,
                    Decision::Blocked => true,
                    _ => false,
                },
                Mode::Reconcile => self.decision == Decision::ComparisonOnly,
                Mode::Register | Mode::ProfileReview | Mode::ProfileReuse | Mode::ProfileCreate | Mode::ProfileReconcile
                | Mode::KeyReview | Mode::KeyPrepare | Mode::KeyRecover | Mode::CertificateReview
                | Mode::CertificateCreate | Mode::CertificateReconcile | Mode::P12Review | Mode::P12Reuse | Mode::P12Save => false,
            }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    observed_at: String,
    valid_until: String,
    before_sha256: String,
    plan_sha256: String,
    request_body_sha256: String,
    update: AttemptUpdate,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Updated {
    update: AttemptUpdate,
}
pub(crate) enum EventData {
    Profile(ProfileEvent),
    Key(KeyEvent),
    Certificate(CertificateEvent),
    P12(P12Event),
    Observed(Observed),
    Pending {
        intent: BundleRegistrationIntent,
        update: AttemptUpdate,
    },
    Attempt(AttemptUpdate),
}
pub(crate) struct EventDataFrame {
    pub(crate) sequence: u32,
    pub(crate) data: EventData,
}

fn update_matches(
    update: &AttemptUpdate,
    binding: &RequestBinding,
    plan: &str,
    sequence: u32,
) -> bool {
    let record = &update.record;
    update.sequence == sequence
        && record.context == binding.scope.provisioning
        && record.plan_sha256 == plan
        && sha(plan)
        && record.action == Action::RegisterBundleId
        && record
            .response_resource_id
            .as_ref()
            .is_none_or(|value| resource_id(value))
        && record
            .observed_resource_id
            .as_ref()
            .is_none_or(|value| resource_id(value))
        && record
            .response_resource_sha256
            .as_ref()
            .is_none_or(|value| sha(value))
        && record.response_resource_id.is_some() == record.response_resource_sha256.is_some()
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    Cancelled,
    ContextChanged,
    DocumentLost,
    Shutdown,
    TimedOut,
    ProtocolError,
    RuntimeUnavailable,
    IntentExpired,
    StaleIntent,
    SavedSourceChanged,
    SavedSourceInvalid,
    CredentialsUnavailable,
    QueryPrerequisites,
    CommandIncomplete,
    CleanupUnknown,
    JournalUnavailable,
    ReviewExpired,
    RegistrationBlocked,
}
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Comparison {
    SameResponse,
    DifferentResponse,
    Unattributed,
    NotReturned,
    Inconclusive,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AttemptSummary {
    operation_id: String,
    action: Action,
    status: AttemptStatus,
    reason: AttemptReason,
    retry_allowed: bool,
    credential_ready: bool,
    cancellation_requested: bool,
}
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Limitation {
    BundleIdOnly,
    NoReleaseOrSigningReadiness,
    NoCertificateOrProfileChanges,
    NoTeamVerification,
    NoGlobalAvailabilityClaim,
    OneWriteNoRetry,
    ParentJournalAndNativeJoinsRequired,
}
const LIMITATIONS: [Limitation; 7] = [
    Limitation::BundleIdOnly,
    Limitation::NoReleaseOrSigningReadiness,
    Limitation::NoCertificateOrProfileChanges,
    Limitation::NoTeamVerification,
    Limitation::NoGlobalAvailabilityClaim,
    Limitation::OneWriteNoRetry,
    Limitation::ParentJournalAndNativeJoinsRequired,
];
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BundleResultData {
    schema_version: u32,
    scope: String,
    mode: Mode,
    pub(crate) observation: Observation,
    pub(crate) decision: Decision,
    #[serde(deserialize_with = "required_option")]
    pub(crate) attempt: Option<AttemptSummary>,
    #[serde(deserialize_with = "required_option")]
    comparison: Option<Comparison>,
    limitations: Vec<Limitation>,
}
impl BundleResultData {
    fn valid(&self, binding: &RequestBinding, last_update: Option<&AttemptUpdate>) -> bool {
        if self.schema_version != 1
            || self.scope != "local-ios-bundle-provisioning"
            || self.mode != binding.context.mode
            || self.limitations.as_slice() != LIMITATIONS
        {
            return false;
        }
        if self.mode == Mode::Reconcile {
            if self.decision != Decision::ComparisonOnly || self.attempt.is_some() {
                return false;
            }
            return match self.comparison {
                Some(
                    Comparison::SameResponse
                    | Comparison::DifferentResponse
                    | Comparison::Unattributed,
                ) => self.observation == Observation::Found,
                Some(Comparison::NotReturned) => self.observation == Observation::NotReturned,
                Some(Comparison::Inconclusive) => !matches!(
                    self.observation,
                    Observation::Found | Observation::NotReturned
                ),
                None => false,
            };
        }
        if self.comparison.is_some() {
            return false;
        }
        if self.mode == Mode::Review {
            return self.attempt.is_none()
                && match self.decision {
                    Decision::Reuse => self.observation == Observation::Found,
                    Decision::ReviewRequired => self.observation == Observation::NotReturned,
                    Decision::Blocked => true,
                    _ => false,
                };
        }
        if let Some(summary) = &self.attempt {
            let Some(update) = last_update else {
                return false;
            };
            let record = &update.record;
            if summary.operation_id != binding.operation
                || summary.action != Action::RegisterBundleId
                || summary.retry_allowed
                || summary.credential_ready
                || summary.status != record.status
                || summary.reason != record.reason
                || summary.cancellation_requested != record.cancel_requested
            {
                return false;
            }
        } else if last_update.is_some() {
            return false;
        }
        match self.decision {
            Decision::RegistrationConfirmed => {
                self.observation == Observation::Found
                    && self
                        .attempt
                        .as_ref()
                        .is_some_and(|attempt| attempt.status == AttemptStatus::Succeeded)
            }
            Decision::RegistrationUnconfirmed => self.attempt.is_some(),
            Decision::Reuse => self.observation == Observation::Found && self.attempt.is_none(),
            Decision::Blocked | Decision::ReviewRequired => self.attempt.is_none(),
            Decision::ComparisonOnly => false,
        }
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum ResultData { Bundle(BundleResultData), Profile(ProfileResult), Key(KeyResult), Certificate(CertificateResult), P12(P12Result) }
impl ResultData {
    pub(crate) fn bundle(&self) -> Option<&BundleResultData> { match self { Self::Bundle(value) => Some(value), _ => None } }
    pub(crate) fn key(&self) -> Option<&KeyResult> { match self { Self::Key(value) => Some(value), _ => None } }
    pub(crate) fn certificate(&self) -> Option<&CertificateResult> { match self { Self::Certificate(value) => Some(value), _ => None } }
    pub(crate) fn p12(&self)->Option<&P12Result> { match self { Self::P12(value)=>Some(value),_=>None } }
    pub(crate) fn profile(&self) -> Option<&ProfileResult> { match self { Self::Profile(value) => Some(value), _ => None } }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CoreStop {
    None,
    Cancelled,
    TimedOut,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Lifetime {
    complete: bool,
    fatal: bool,
    contained: bool,
    #[serde(deserialize_with = "required_option")]
    command_dispatched: Option<bool>,
    commands: u32,
    profile_calls: u32,
    input_closed: bool,
    handlers_restored: bool,
    invocation_closed: bool,
    stop_observed: CoreStop,
}
impl Lifetime {
    pub(crate) fn settled(&self) -> bool { self.settled_for(Mode::Review) }
    pub(crate) fn settled_for(&self, mode: Mode) -> bool {
        self.complete
            && !self.fatal
            && self.contained
            && self.command_dispatched.is_some()
            && self.profile_calls <= u32::from(mode.profile() || mode.p12())
            && self.input_closed
            && self.handlers_restored
            && self.invocation_closed
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Terminal {
    schema_version: u32,
    context: Context,
    pub(crate) outcome: Outcome,
    pub(crate) reason: Reason,
    #[serde(deserialize_with = "required_option")]
    pub(crate) result: Option<ResultData>,
    pub(crate) lifetime: Lifetime,
}
impl Terminal {
    /// The retained operation mode is public protocol data; keep the full
    /// context private and do not treat this accessor as native finality.
    pub(crate) fn mode(&self) -> Mode {
        self.context.mode
    }
    /// Original owner dispatch must use this retained mode, not the Bundle-only
    /// default. This is protocol settlement DATA, never native join authority.
    pub(crate) fn settled(&self) -> bool {
        self.lifetime.settled_for(self.context.mode)
    }
    fn valid(
        &self,
        binding: &RequestBinding,
        last_update: Option<&AttemptUpdate>,
        observed: bool,
        profile: &profile::ProfileDecoder,
        key: &key::KeyDecoder,
        certificate: &certificate::CertificateDecoder,
        p12: &p12::P12Decoder,
    ) -> bool {
        let life = &self.lifetime;
        if self.schema_version != 1
            || self.context != binding.context
            || !self.context.valid()
            || life.commands > self.context.mode.commands()
            || life.profile_calls > u32::from(self.context.mode.profile() || self.context.mode.p12())
            || !key.lifetime_matches(life)
        {
            return false;
        }
        if self.outcome == Outcome::Complete {
            return self.reason == Reason::None
                && life.settled_for(self.context.mode)
                && life.command_dispatched == Some(true)
                && (Mode::Review.commands()..=self.context.mode.commands())
                    .contains(&life.commands)
                && life.stop_observed == CoreStop::None
                && (self.context.mode.key() || self.context.mode.profile() || self.context.mode == Mode::Register || observed)
                && self.result.as_ref().is_some_and(|result| match result {
                    ResultData::Bundle(result) => !self.context.mode.profile() && !self.context.mode.key() && result.valid(binding, last_update),
                    ResultData::Profile(result) => self.context.mode.profile() && profile.valid_terminal(result, binding),
                    ResultData::Key(result) => (self.context.mode.local_key() || self.context.mode == Mode::KeyRecover) && key.valid_terminal(result, binding),
                    ResultData::P12(result) => self.context.mode.p12() && p12.valid_terminal(result,binding),
                    ResultData::Certificate(result) => self.context.mode.certificate() && certificate.valid_terminal(result, binding),
                });
        }
        if self.result.is_some() || self.reason == Reason::None {
            return false;
        }
        if self.outcome == Outcome::Unknown {
            return self.reason == Reason::CleanupUnknown && !life.settled_for(self.context.mode);
        }
        if !life.settled_for(self.context.mode) {
            return false;
        }
        match self.outcome {
            Outcome::Cancelled => {
                self.reason == Reason::Cancelled && life.stop_observed == CoreStop::Cancelled
            }
            Outcome::TimedOut => {
                self.reason == Reason::TimedOut && life.stop_observed == CoreStop::TimedOut
            }
            Outcome::Refused | Outcome::Failed => true,
            _ => false,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    protocol: String,
    operation_id: String,
    owner_generation: String,
    nonce: String,
    request_sha256: String,
    sequence: u32,
    kind: String,
    payload: Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Accepted {
    schema_version: u32,
    context: Context,
}
pub(crate) enum Frame {
    Accepted,
    Event(EventDataFrame),
    Terminal(Terminal),
}
pub(crate) struct Decoder {
    binding: Arc<RequestBinding>,
    next: u32,
    total: usize,
    failed: bool,
    terminal: bool,
    observed: bool,
    plan: Option<String>,
    last_update: Option<AttemptUpdate>,
    profile: profile::ProfileDecoder,
    key: key::KeyDecoder,
    certificate: certificate::CertificateDecoder,
    p12: p12::P12Decoder,
}
impl Decoder {
    pub(crate) fn new(binding: Arc<RequestBinding>) -> Self {
        Self {
            binding,
            next: 0,
            total: 0,
            failed: false,
            terminal: false,
            observed: false,
            plan: None,
            last_update: None,
            profile: profile::ProfileDecoder::default(),
            key: key::KeyDecoder::default(),
            certificate: certificate::CertificateDecoder::default(),
            p12: p12::P12Decoder::default(),
        }
    }
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<Frame, BridgeError> {
        let result = self.decode(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result.map_err(|_| BridgeError::protocol())
    }
    fn decode(&mut self, bytes: &[u8]) -> Result<Frame, BridgeError> {
        need(
            !self.failed
                && !self.terminal
                && (3..=self.binding.context.mode.frame_limit()).contains(&bytes.len())
                && bytes[0] == b'{'
                && bytes.ends_with(b"}\n")
                && !bytes[..bytes.len() - 1]
                    .iter()
                    .any(|byte| matches!(byte, b'\r' | b'\n')),
        )?;
        self.total = self.total.checked_add(bytes.len()).ok_or_else(invalid)?;
        need(self.total <= self.binding.context.mode.response_limit())?;
        let value = strict_json(&bytes[..bytes.len() - 1]).map_err(|_| invalid())?;
        let envelope = Envelope::deserialize(value).map_err(|_| invalid())?;
        let binding = &self.binding;
        need(
            envelope.protocol == PROTOCOL
                && envelope.operation_id == binding.operation
                && envelope.owner_generation == binding.generation
                && envelope.nonce == binding.nonce
                && envelope.request_sha256 == binding.sha256
                && envelope.sequence == self.next,
        )?;
        let frame = match envelope.kind.as_str() {
            "accepted" => {
                need(self.next == 0)?;
                let accepted = Accepted::deserialize(envelope.payload).map_err(|_| invalid())?;
                need(accepted.schema_version == 1 && accepted.context == binding.context)?;
                Frame::Accepted
            }
            "terminal" => {
                need(self.next > 0 && self.next <= binding.context.mode.events() + 1)?;
                let terminal = Terminal::deserialize(envelope.payload).map_err(|_| invalid())?;
                need(terminal.valid(binding, self.last_update.as_ref(), self.observed, &self.profile, &self.key, &self.certificate, &self.p12))?;
                self.terminal = true;
                Frame::Terminal(terminal)
            }
            "observed" => {
                need(
                    self.next == 1
                        && matches!(binding.context.mode, Mode::Review | Mode::Reconcile)
                        && bytes.len() <= EVENT_LIMIT,
                )?;
                let observed = Observed::deserialize(envelope.payload).map_err(|_| invalid())?;
                need(observed.valid(binding))?;
                self.observed = true;
                Frame::Event(EventDataFrame {
                    sequence: self.next,
                    data: EventData::Observed(observed),
                })
            }
            "pending" => {
                need(
                    self.next == 1
                        && binding.context.mode == Mode::Register
                        && bytes.len() <= EVENT_LIMIT,
                )?;
                let pending = Pending::deserialize(envelope.payload).map_err(|_| invalid())?;
                need(
                    binding.scope.reviewed_at.as_ref() == Some(&pending.observed_at)
                        && update_matches(
                            &pending.update,
                            binding,
                            &pending.plan_sha256,
                            self.next,
                        ),
                )?;
                let record = &pending.update.record;
                need(
                    record.status == AttemptStatus::Running
                        && record.reason == AttemptReason::ReadbackRequired
                        && record.possible_send
                        && !record.cancel_requested
                        && record.response_resource_id.is_none()
                        && record.observed_resource_id.is_none(),
                )?;
                let intent = BundleRegistrationIntent {
                    context: binding.scope.provisioning.clone(),
                    provenance: binding.scope.provenance.clone(),
                    target: binding.scope.target.clone(),
                    observed_at: pending.observed_at,
                    valid_until: pending.valid_until,
                    before_sha256: pending.before_sha256,
                    plan_sha256: pending.plan_sha256,
                    request_body_sha256: pending.request_body_sha256,
                };
                intent.validate().map_err(|_| invalid())?;
                self.plan = Some(intent.plan_sha256.clone());
                self.last_update = Some(pending.update.clone());
                Frame::Event(EventDataFrame {
                    sequence: self.next,
                    data: EventData::Pending {
                        intent,
                        update: pending.update,
                    },
                })
            }
            "attempt" => {
                need(
                    (2..=MAX_EVENTS).contains(&self.next)
                        && binding.context.mode == Mode::Register
                        && bytes.len() <= EVENT_LIMIT,
                )?;
                let update = Updated::deserialize(envelope.payload)
                    .map_err(|_| invalid())?
                    .update;
                need(update_matches(
                    &update,
                    binding,
                    self.plan.as_ref().ok_or_else(invalid)?,
                    self.next,
                ))?;
                // Service validates the exact monotone transition before any
                // ACK. Decoder only holds provisional stream comparison DATA.
                self.last_update = Some(update.clone());
                Frame::Event(EventDataFrame {
                    sequence: self.next,
                    data: EventData::Attempt(update),
                })
            }
            kind @ ("certificate-key" | "certificate-identities" | "certificate-policy" | "certificate-observed" | "certificate-pending" | "certificate-attempt") => {
                need((binding.context.mode.certificate() || binding.context.mode.p12() && matches!(kind,"certificate-key"|"certificate-identities"|"certificate-policy"))
                    && (kind == "certificate-identities" || bytes.len() <= EVENT_LIMIT))?;
                Frame::Event(EventDataFrame { sequence: self.next, data: EventData::Certificate(
                    self.certificate.event(binding, self.next, kind, envelope.payload)?) })
            },
            kind @ ("p12-observed"|"p12-pending"|"p12-output") => {
                need(binding.context.mode.p12() && bytes.len()<=EVENT_LIMIT)?;
                Frame::Event(EventDataFrame { sequence:self.next, data:EventData::P12(self.p12.event(binding,self.next,kind,envelope.payload)?) })
            },
            kind @ ("key-observed" | "key-pending" | "key-output" | "key-not-generated" | "key-compared") => {
                need((binding.context.mode.local_key() || binding.context.mode == Mode::KeyRecover) && bytes.len() <= EVENT_LIMIT)?;
                Frame::Event(EventDataFrame { sequence: self.next,
                    data: EventData::Key(self.key.event(binding, self.next, kind, envelope.payload)?) })
            },
            kind @ ("identity" | "profile-observed" | "profile-pending" | "profile-attempt") => {
                need(binding.context.mode.profile() && (kind == "identity" || bytes.len() <= EVENT_LIMIT))?;
                Frame::Event(EventDataFrame { sequence: self.next,
                    data: EventData::Profile(self.profile.event(binding, self.next, kind, envelope.payload)?) })
            },
            _ => return Err(invalid()),
        };
        self.next = self.next.checked_add(1).ok_or_else(invalid)?;
        Ok(frame)
    }
    pub(crate) fn settled(&self) -> bool {
        !self.failed && self.terminal
    }
}

/// Called by the original writer ONLY after the journal job actually joined
/// and its currentness check passed. This serializer itself grants no send.
pub(crate) fn journal_ack(
    binding: &RequestBinding,
    ack: &JournalAck,
    expected: &AttemptUpdate,
    previous_revision: crate::application_state_store::Revision,
) -> Result<Vec<u8>, BridgeError> {
    need(
        binding.context.mode == Mode::Register
            && (1..=MAX_EVENTS).contains(&expected.sequence)
            && ack.revision.0 == previous_revision.0.checked_add(1).ok_or_else(invalid)?
            && ack.row.intent.context == binding.scope.provisioning
            && ack.row.intent.target == binding.scope.target
            && ack.row.intent.provenance == binding.scope.provenance
            && ack.original.intent() == &ack.row.intent
            && &ack.row.attempt == expected
            && ack.row.send_armed
            && ack.row.native_settlement
                == crate::apple_provisioning_journal::NativeSettlement::Pending,
    )?;
    let record_sha256 = expected.sha256().map_err(|_| invalid())?;
    let value = json!({"protocol":PROTOCOL,"operationId":binding.operation,"ownerGeneration":binding.generation,
        "nonce":binding.nonce,"requestSha256":binding.sha256,"kind":"journal-ack","step":expected.sequence,
        "payload":{"revision":ack.revision.0,"sequence":expected.sequence,"recordSha256":record_sha256}});
    let mut bytes = bounded(&value, ACK_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Projection {
    pub(crate) operation_id: String,
    pub(crate) owner_generation: String,
    pub(crate) context: Context,
    pub(crate) phase: Phase,
    pub(crate) intent_usable: bool,
    pub(crate) outcome: Option<Outcome>,
    pub(crate) reason: Reason,
    pub(crate) result: Option<ResultData>,
    pub(crate) recovery: Option<RecoveryHistory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) profile_recovery: Option<ProfileRecoveryHistory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) certificate_recovery: Option<CertificateRecoveryHistory>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub(crate) saved_profile: Option<crate::credential_setup::KeyReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) saved_key: Option<crate::credential_setup::KeyReference>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub(crate) saved_p12: Option<crate::credential_setup::KeyReference>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32,
    pub(crate) status_revision: u32,
    pub(crate) availability: Availability,
    pub(crate) operation: Option<Projection>,
}

#[cfg(test)]
#[path = "apple_provisioning_protocol_tests.rs"]
mod tests;
