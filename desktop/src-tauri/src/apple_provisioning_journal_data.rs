//! Closed reference-only DATA for the initial Bundle-ID registration journal.
//! Shapes/hashes compare the existing Python plan; they never grant a command,
//! authenticate a key, renew consent or establish original native finality.
use crate::{
    android_build_protocol::{Content, SavedVersion},
    application_service::ProjectBinding,
    application_state_store::StateError,
    service_protocol::{hex, Error, Id},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    path::{Component, Path},
};

pub(super) const PROTOCOL: &str = "mrk-apple-provisioning-journal/1";
// Representation bounds for the original native owner's existing admission.
// They are not RSS caps: raw/Value/typed/encode/readback can coexist in one job.
pub(crate) const ROW_LIMIT: usize = 16 * 1024;
pub(crate) const ROWS: usize = 32;
pub(crate) const STATE_LIMIT: usize = 1024 * 1024;
pub(crate) const ATTEMPT_LIMIT: u32 = 64;
type Result<T> = std::result::Result<T, StateError>;

pub(super) fn need(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::InvalidRequest.into())
    }
}
#[path = "apple_provisioning_profile_journal_data.rs"]
pub(super) mod profile;
pub(crate) use profile::{ProfileAction, ProfileTarget, ProfileBundle, ProfileCertificate, ProfileSelection,
    ProfileSetupIntent, ProfileCreateAction, ProfileAttemptRecord, ProfileProvider, ProfileDownload,
    ProfileSaveState, ProfileUpdate, ProfileSetupRow, PROFILE_PROTOCOL, PROFILE_BYTES};

#[path = "apple_provisioning_key_journal_data.rs"]
pub(super) mod key;
pub(crate) use key::{KeyAlgorithm, KeyPrepareIntent, KeyOutputMetadata, KeyGeneration, KeyDisposition,
    KeyPrepareUpdate, KeyPrepareRow, CertificateIssuanceIntent, CertificateCreateAction,
    CertificateAttemptRecord, CertificateCreationReceipt, CertificateUpdate, CertificateIssuanceRow, KEY_PROTOCOL};

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}
fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Account equality is derived ONLY by the native selected-P8 owner from the
/// decoded issuer UUID. Deserialization below restores comparison DATA, not
/// selected-key authority. Key rotation/project changes do not change this key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct AccountRef(String);
impl AccountRef {
    pub(crate) fn from_selected_issuer(uuid: [u8; 16]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"mrk:apple-provisioning-account:1\0");
        hash.update(uuid);
        Self(hex(&hash.finalize()))
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for AccountRef {
    type Error = Error;
    fn try_from(value: String) -> std::result::Result<Self, Error> {
        if sha(&value) {
            Ok(Self(value))
        } else {
            Err(Error::InvalidRequest)
        }
    }
}
impl From<AccountRef> for String {
    fn from(value: AccountRef) -> Self {
        value.0
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProvisioningContext {
    // Existing native runtime context. This is deliberately separate from
    // provenance.project_binding.project_id, the original durable service ID.
    pub(crate) project_id: String,
    pub(crate) client_id: String,
    pub(crate) operation_id: String,
    pub(crate) observation_revision: u32,
    pub(crate) account_ref: AccountRef,
    pub(crate) credential_record_id: String,
    pub(crate) credential_revision: u32,
    pub(crate) credential_context_revision: u32,
}
impl ProvisioningContext {
    fn valid(&self) -> bool {
        identifier(&self.project_id)
            && identifier(&self.client_id)
            && Id::parse(&self.operation_id).is_ok()
            && identifier(&self.credential_record_id)
            && self.observation_revision > 0
            && self.credential_revision > 0
            && self.credential_context_revision > 0
    }
    fn core_value(&self) -> Value {
        // Python dataclasses.asdict uses these exact snake_case member names.
        json!({"project_id":self.project_id,"client_id":self.client_id,
            "operation_id":self.operation_id,"observation_revision":self.observation_revision,
            "account_ref":self.account_ref,"credential_record_id":self.credential_record_id,
            "credential_revision":self.credential_revision,
            "credential_context_revision":self.credential_context_revision})
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RegisteredRootData {
    pub(crate) path: String,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NativeProvenance {
    pub(crate) project_binding: ProjectBinding,
    pub(crate) operation_id: Id,
    pub(crate) owner_generation: Id,
    pub(crate) registration_generation: u32,
    pub(crate) registered_root: RegisteredRootData,
    pub(crate) draft_revision: u32,
    pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content,
    pub(crate) saved_version: SavedVersion,
}
impl NativeProvenance {
    fn valid(&self) -> bool {
        let root = &self.registered_root;
        let path = Path::new(&root.path);
        root.inode > 0
            && root.mode & 0o170000 == 0o040000
            && path.is_absolute()
            && !root.path.is_empty()
            && root.path.len() <= 3500
            && !root.path.contains("//")
            && !root.path.ends_with('/')
            && !root.path.chars().any(|ch| ch.is_control())
            && root.path.split('/').all(|part| part != "." && part != "..")
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            && self.project_binding.canonical_root == root.path
            && (self.project_binding.device, self.project_binding.inode)
                == (root.device, root.inode)
            && self.registration_generation > 0
            && self.draft_revision < u32::MAX
            && self.baseline_generation < u32::MAX
            && self.saved_config.valid(524_288)
            && self.saved_version.valid()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BundleTarget {
    pub(crate) bundle_id: String,
    pub(crate) team_id: String,
    pub(crate) app_id_prefix: String,
    pub(crate) display_name: String,
    pub(crate) existing_application: bool,
}
impl BundleTarget {
    fn valid(&self) -> bool {
        let team = |value: &str| {
            value.len() == 10
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        };
        !self.existing_application
            && self.bundle_id.len() <= 255
            && self.bundle_id.split('.').count() >= 2
            && self.bundle_id.split('.').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            && team(&self.team_id)
            && team(&self.app_id_prefix)
            && self.app_id_prefix == self.team_id
            && !self.display_name.is_empty()
            && self.display_name.chars().count() <= 128
            && !self
                .display_name
                .chars()
                .any(|ch| ch < '\u{20}' || ch == '\u{7f}')
    }
    fn core_value(&self) -> Value {
        json!({"bundle_id":self.bundle_id,"team_id":self.team_id,"app_id_prefix":self.app_id_prefix,
            "display_name":self.display_name,"existing_application":false,
            "entitlements_json":hex(&Sha256::digest(b"{}"))})
    }
    fn request_body(&self) -> Value {
        json!({"data":{"type":"bundleIds","attributes":{
            "identifier":self.bundle_id,"name":self.display_name,"platform":"IOS"}}})
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BundleRegistrationIntent {
    pub(crate) context: ProvisioningContext,
    pub(crate) provenance: NativeProvenance,
    pub(crate) target: BundleTarget,
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) before_sha256: String,
    pub(crate) plan_sha256: String,
    pub(crate) request_body_sha256: String,
}
impl BundleRegistrationIntent {
    pub(crate) fn validate(&self) -> Result<()> {
        need(
            self.context.valid()
                && self.provenance.valid()
                && self.target.valid()
                && self.provenance.operation_id.as_str() == self.context.operation_id
                && [
                    &self.before_sha256,
                    &self.plan_sha256,
                    &self.request_body_sha256,
                ]
                .into_iter()
                .all(|value| sha(value)),
        )?;
        let observed =
            utc_micros(&self.observed_at).ok_or_else(|| StateError::from(Error::InvalidRequest))?;
        let until =
            utc_micros(&self.valid_until).ok_or_else(|| StateError::from(Error::InvalidRequest))?;
        need(until.checked_sub(observed) == Some(300_000_000))?;
        // Only the COMPLETE/AVAILABLE/EMPTY Bundle-ID before inventory is
        // representable. Certificate/profile/entitlement plans cannot hide in
        // arbitrary JSON or substitute an empty broader signing observation.
        let before = json!({"context":self.context.core_value(),"bundleId":self.target.bundle_id,
            "scope":"bundle-identifiers","available":true,"reason":"observed",
            "bundles":[],"certificates":[],"profiles":[]});
        need(
            hash(&before)? == self.before_sha256
                && hash(&self.target.request_body())? == self.request_body_sha256,
        )?;
        let plan = json!({"context":self.context.core_value(),"target":self.target.core_value(),
            "observation":self.before_sha256,"validUntil":self.valid_until,
            "action":"register_bundle_id","reason":"new_application_registration_requires_approval",
            "request":{"kind":"register_bundle_id","method":"POST","path":"/v1/bundleIds",
                "query":[],"bodySha256":self.request_body_sha256},
            "binding":null,"selection":{"bundle":null,"certificate":null,"profile":null},"csr":null});
        need(hash(&plan)? == self.plan_sha256)?;
        canonical(self, ROW_LIMIT).map(|_| ())
    }
}

/// Canonical Python datetime.isoformat UTC, no clock/freshness authority. Store
/// exactly the supplied spelling; neither native epochs nor IDs are normalized.
fn utc_micros(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if ![25, 32].contains(&bytes.len()) || !value.is_ascii() || !value.ends_with("+00:00") {
        return None;
    }
    if !bytes[..19].iter().enumerate().all(|(i, byte)| match i {
        4 | 7 => *byte == b'-',
        10 => *byte == b'T',
        13 | 16 => *byte == b':',
        _ => byte.is_ascii_digit(),
    }) {
        return None;
    }
    let n = |a, b| {
        bytes[a..b]
            .iter()
            .fold(0u64, |value, byte| value * 10 + u64::from(byte - b'0'))
    };
    let (year, month, day, hour, minute, second) =
        (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16), n(17, 19));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    if year == 0 || day == 0 || day > days || hour >= 24 || minute >= 60 || second >= 60 {
        return None;
    }
    let fraction = if bytes.len() == 32 {
        if bytes[19] != b'.' || !bytes[20..26].iter().all(u8::is_ascii_digit) {
            return None;
        }
        let micros = n(20, 26);
        if micros == 0 {
            return None;
        } // Python omits the fraction at zero.
        micros
    } else {
        0
    };
    let before_year = year - 1;
    let before_month = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334][month as usize - 1];
    let total_days = 365 * before_year + before_year / 4 - before_year / 100
        + before_year / 400
        + before_month
        + u64::from(leap && month > 2)
        + day
        - 1;
    Some((((total_days * 24 + hour) * 60 + minute) * 60 + second) * 1_000_000 + fraction)
}

pub(super) fn canonical<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
    let mut value =
        serde_json::to_value(value).map_err(|_| StateError::from(Error::InvalidRequest))?;
    value.sort_all_objects();
    let utf8 =
        serde_json::to_string(&value).map_err(|_| StateError::from(Error::InvalidRequest))?;
    need(utf8.len() <= limit)?;
    let mut ascii = String::with_capacity(utf8.len());
    for ch in utf8.chars() {
        if ch < '\u{7f}' {
            ascii.push(ch);
        } else {
            for unit in ch.encode_utf16(&mut [0u16; 2]).iter() {
                write!(&mut ascii, "\\u{unit:04x}")
                    .map_err(|_| StateError::from(Error::InvalidRequest))?;
            }
        }
        need(ascii.len() <= limit)?;
    }
    Ok(ascii.into_bytes())
}
fn hash<T: Serialize>(value: &T) -> Result<String> {
    Ok(hex(&Sha256::digest(canonical(value, ROW_LIMIT)?)))
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    RegisterBundleId,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AttemptStatus {
    Running,
    CancellationRequested,
    Succeeded,
    Failed,
    Cancelled,
    RecoveryRequired,
    Unknown,
}
impl AttemptStatus {
    pub(super) fn terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AttemptReason {
    ReadbackRequired,
    JournalSettlementRequired,
    AuthorizationChanged,
    CancelledBeforeSend,
    ProviderOutcomeUnknown,
    OriginalTransportUnsettled,
    AuthorizationChangedAfterSend,
    ProviderRejectedRequest,
    ProviderResultRequiresReconciliation,
    ReconciliationReadUnavailable,
    ReconciliationContextChanged,
    ResourceValidationRequired,
    ProviderOutcomeStillUnknown,
    AmbiguousRecoveryResources,
    ResourceFoundReviewRequired,
    ResponseReadbackDisagrees,
    ProviderResourceConfirmed,
    CancelledAfterSettlement,
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    decoder: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(decoder)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AttemptRecord {
    pub(crate) context: ProvisioningContext,
    pub(crate) plan_sha256: String,
    pub(crate) action: Action,
    pub(crate) status: AttemptStatus,
    pub(crate) reason: AttemptReason,
    pub(crate) possible_send: bool,
    #[serde(deserialize_with = "required_option")]
    pub(crate) response_resource_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) response_resource_sha256: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub(crate) observed_resource_id: Option<String>,
    pub(crate) cancel_requested: bool,
}
impl AttemptRecord {
    fn validate(&self, intent: &BundleRegistrationIntent) -> Result<()> {
        self.validate_fields(&intent.context, &intent.plan_sha256)
    }
    fn validate_fields(&self, context: &ProvisioningContext, plan_sha256: &str) -> Result<()> {
        use AttemptReason as R;
        use AttemptStatus as S;
        need(
            &self.context == context
                && self.plan_sha256 == plan_sha256
                && self
                    .response_resource_id
                    .as_ref()
                    .is_none_or(|id| identifier(id))
                && self
                    .observed_resource_id
                    .as_ref()
                    .is_none_or(|id| identifier(id))
                && self
                    .response_resource_sha256
                    .as_ref()
                    .is_none_or(|value| sha(value))
                && self.response_resource_id.is_some() == self.response_resource_sha256.is_some(),
        )?;
        let shape = match self.status {
            S::Running => self.reason == R::ReadbackRequired && self.possible_send,
            S::CancellationRequested => self.cancel_requested && self.possible_send,
            S::Succeeded => self.reason == R::ProviderResourceConfirmed && !self.cancel_requested,
            S::Failed => matches!(
                self.reason,
                R::AuthorizationChanged | R::ProviderRejectedRequest
            ),
            S::Cancelled => {
                self.cancel_requested
                    && matches!(
                        self.reason,
                        R::CancelledBeforeSend
                            | R::ProviderRejectedRequest
                            | R::CancelledAfterSettlement
                    )
            }
            S::RecoveryRequired => matches!(
                self.reason,
                R::ReadbackRequired
                    | R::JournalSettlementRequired
                    | R::ResourceValidationRequired
                    | R::ResourceFoundReviewRequired
            ),
            S::Unknown => matches!(
                self.reason,
                R::ProviderOutcomeUnknown
                    | R::OriginalTransportUnsettled
                    | R::AuthorizationChangedAfterSend
                    | R::ProviderResultRequiresReconciliation
                    | R::ReconciliationReadUnavailable
                    | R::ReconciliationContextChanged
                    | R::ProviderOutcomeStillUnknown
                    | R::AmbiguousRecoveryResources
                    | R::ResponseReadbackDisagrees
            ),
        };
        need(shape)?;
        if !self.possible_send {
            need(
                self.response_resource_id.is_none()
                    && self.observed_resource_id.is_none()
                    && matches!(
                        (self.status, self.reason),
                        (S::Failed, R::AuthorizationChanged)
                            | (S::Cancelled, R::CancelledBeforeSend)
                            | (S::RecoveryRequired, R::JournalSettlementRequired)
                    ),
            )?;
        }
        if matches!(
            self.reason,
            R::ProviderResourceConfirmed | R::CancelledAfterSettlement
        ) {
            need(
                self.possible_send
                    && self.response_resource_id.is_some()
                    && self.response_resource_id == self.observed_resource_id,
            )?;
        }
        if self.reason == R::CancelledBeforeSend {
            need(!self.possible_send)?;
        }
        if self.reason == R::AuthorizationChanged {
            need(!self.possible_send)?;
        }
        if self.reason == R::ProviderRejectedRequest {
            need(
                self.possible_send
                    && self.response_resource_id.is_none()
                    && self.observed_resource_id.is_none(),
            )?;
        }
        Ok(())
    }
    fn original_no_send(&self) -> bool {
        matches!(
            (self.status, self.reason),
            (AttemptStatus::Failed, AttemptReason::AuthorizationChanged)
                | (AttemptStatus::Cancelled, AttemptReason::CancelledBeforeSend)
        ) && !self.possible_send
            && self.response_resource_id.is_none()
            && self.observed_resource_id.is_none()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AttemptUpdate {
    pub(crate) sequence: u32,
    pub(crate) record: AttemptRecord,
}
impl AttemptUpdate {
    /// Bounded canonical DATA comparison for the original ACK dialogue, not
    /// proof of authorization, durable publication or native settlement.
    pub(crate) fn sha256(&self) -> Result<String> {
        hash(self)
    }
    pub(super) fn armed(&self, intent: &BundleRegistrationIntent) -> Result<()> {
        self.record.validate(intent)?;
        need(
            self.sequence == 1
                && self.record.status == AttemptStatus::Running
                && self.record.reason == AttemptReason::ReadbackRequired
                && self.record.possible_send
                && self.record.response_resource_id.is_none()
                && self.record.observed_resource_id.is_none(),
        )
    }
    pub(super) fn follows(&self, previous: &Self, intent: &BundleRegistrationIntent) -> Result<()> {
        self.follows_fields(previous, &intent.context, &intent.plan_sha256)
    }
    fn follows_fields(&self, previous: &Self, context: &ProvisioningContext, plan_sha256: &str) -> Result<()> {
        self.record.validate_fields(context, plan_sha256)?;
        let old = &previous.record;
        let next = &self.record;
        need(
            self.sequence <= ATTEMPT_LIMIT
                && previous.sequence.checked_add(1) == Some(self.sequence)
                && !old.status.terminal()
                && next.status != AttemptStatus::Running
                && (!old.cancel_requested || next.cancel_requested)
                && old
                    .response_resource_id
                    .as_ref()
                    .is_none_or(|id| next.response_resource_id.as_ref() == Some(id))
                && old
                    .response_resource_sha256
                    .as_ref()
                    .is_none_or(|sha| next.response_resource_sha256.as_ref() == Some(sha))
                && old
                    .observed_resource_id
                    .as_ref()
                    .is_none_or(|id| next.observed_resource_id.as_ref() == Some(id)),
        )?;
        if next.status == AttemptStatus::CancellationRequested {
            // Actual Python request_cancel changes only status/cancel_requested.
            // Preserving the old reason and every send/response fact prevents
            // Unknown -> cancellation -> apparent pre-send refusal laundering.
            let mut cancelled = old.clone();
            cancelled.status = AttemptStatus::CancellationRequested;
            cancelled.cancel_requested = true;
            need(next == &cancelled)?;
        }
        if next.status == AttemptStatus::RecoveryRequired
            && next.reason == AttemptReason::ReadbackRequired
        {
            // Only the original POST response creates this state. An uncertain
            // GET/cancellation cannot restore the initial pre-response reason.
            need(
                matches!(
                    old.status,
                    AttemptStatus::Running | AttemptStatus::CancellationRequested
                ) && old.reason == AttemptReason::ReadbackRequired
                    && old.response_resource_id.is_none()
                    && next.response_resource_id.is_some(),
            )?;
        }
        if old.possible_send && !next.possible_send {
            need(
                matches!(
                    old.status,
                    AttemptStatus::Running | AttemptStatus::CancellationRequested
                ) && old.reason == AttemptReason::ReadbackRequired
                    && next.original_no_send(),
            )?;
        }
        if matches!(
            old.status,
            AttemptStatus::Unknown | AttemptStatus::RecoveryRequired
        ) {
            need(
                next.status != AttemptStatus::Failed
                    && next.reason != AttemptReason::CancelledBeforeSend,
            )?;
        }
        if next.reason == AttemptReason::ProviderRejectedRequest
            || old.response_resource_id.is_none() && next.response_resource_id.is_some()
        {
            // These facts come only from the original POST result, never from
            // a later GET which happens to find a similarly named resource.
            need(
                matches!(
                    old.status,
                    AttemptStatus::Running | AttemptStatus::CancellationRequested
                ) && old.reason == AttemptReason::ReadbackRequired,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeSettlement {
    Pending,
    Known,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct JournalRow {
    pub(crate) intent: BundleRegistrationIntent,
    pub(crate) send_armed: bool,
    pub(crate) attempt: AttemptUpdate,
    pub(crate) native_settlement: NativeSettlement,
}
impl JournalRow {
    pub(super) fn validate(&self) -> Result<()> {
        self.intent.validate()?;
        need(self.send_armed && (1..=ATTEMPT_LIMIT).contains(&self.attempt.sequence))?;
        self.attempt.record.validate(&self.intent)?;
        if self.attempt.sequence == 1 {
            self.attempt.armed(&self.intent)?;
        }
        canonical(self, ROW_LIMIT).map(|_| ())
    }
    pub(crate) fn unresolved(&self) -> bool {
        self.native_settlement != NativeSettlement::Known || !self.attempt.record.status.terminal()
    }
}

#[cfg(test)]
#[path = "apple_provisioning_journal_data_tests.rs"]
pub(super) mod tests;
