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
pub(crate) use recovery_selection::{
    recovery_history, recovery_scope_matches, RecoveryHistory, RECOVERY_LIMIT,
};
#[cfg(test)]
pub(crate) use recovery_selection::tests::sample as recovery_comparison_fixture;

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
}
impl Mode {
    pub(crate) fn consent(self) -> &'static str {
        match self {
            Self::Review => "local-ios-bundle-review-v1",
            Self::Register => "local-ios-bundle-register-v1",
            Self::Reconcile => "local-ios-bundle-reconcile-v1",
        }
    }
    pub(crate) fn commands(self) -> u32 {
        if self == Self::Register {
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
}
impl Context {
    pub(crate) fn valid(&self) -> bool {
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
            && if self.mode == Mode::Review {
                self.reference.is_none()
            } else {
                self.reference.as_ref().is_some_and(Reference::valid)
            }
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
    need(keys(
        value,
        &[
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
        ],
    ))?;
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
            && [Mode::Review, Mode::Register, Mode::Reconcile]
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
            && if context.mode == Mode::Register {
                !t.existing_application
                    && t.team_id == t.app_id_prefix
                    && self
                        .reviewed_at
                        .as_ref()
                        .is_some_and(|value| timestamp_shape(value))
            } else {
                self.reviewed_at.is_none()
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
    scope: ScopeData,
    account: &AccountSnapshot,
    prior: Option<&JournalRow>,
) -> Result<EncodedRequest, BridgeError> {
    need(
        token(operation)
            && token(generation)
            && context.valid()
            && token(&nonce)
            && credential_config.valid(524288)
            && credential_config == &context.saved_config
            && scope.matches(context, operation, generation, root)
            && account.account == scope.provisioning.account_ref
            && account.rows.len() <= ROWS
            // Reserve, up to two attempt writes, then final native CAS. Do not
            // arm a provider write if this fixed whole path can overflow.
            && account.revision.0 <= u64::MAX - 4
            && work_end_ns > 0
            && work_end_ns < hard_end_ns
            && hard_end_ns - work_end_ns <= 10_000_000_000,
    )?;
    let mut seen = std::collections::BTreeSet::new();
    need(account.rows.iter().all(|row| {
        row.intent.context.account_ref == account.account
            && seen.insert(row.intent.context.operation_id.as_str())
    }))?;
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
    let pending: Vec<_> = account.rows.iter().map(|row| json!({
        "accountRef":row.intent.context.account_ref,"operationId":row.intent.context.operation_id,
        "action":row.attempt.record.action,"status":row.attempt.record.status,"nativeSettlement":row.native_settlement,
    })).collect();
    let identity = root
        .identity
        .posix()
        .map_err(|_| invalid())?
        .preflight_identity();
    let value = json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&root.path).ok_or_else(invalid)?,"rootIdentity":identity,
            "cwd":native_path(cwd).ok_or_else(invalid)?,"credentialConfig":credential_config,
            "clock":{"workEndNs":work_end_ns.to_string(),"hardEndNs":hard_end_ns.to_string()},"nonce":nonce,
            "provisioning":scope.provisioning,"target":scope.target,"reviewedAt":scope.reviewed_at,
            "journalRevision":account.revision.0,"pending":pending,"prior":prior}});
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
                Mode::Register => false,
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
pub(crate) struct ResultData {
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
impl ResultData {
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
    pub(crate) fn settled(&self) -> bool {
        self.complete
            && !self.fatal
            && self.contained
            && self.command_dispatched.is_some()
            && self.profile_calls == 0
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
    fn valid(
        &self,
        binding: &RequestBinding,
        last_update: Option<&AttemptUpdate>,
        observed: bool,
    ) -> bool {
        let life = &self.lifetime;
        if self.schema_version != 1
            || self.context != binding.context
            || !self.context.valid()
            || life.commands > self.context.mode.commands()
            || life.profile_calls != 0
        {
            return false;
        }
        if self.outcome == Outcome::Complete {
            return self.reason == Reason::None
                && life.settled()
                && life.command_dispatched == Some(true)
                && (Mode::Review.commands()..=self.context.mode.commands())
                    .contains(&life.commands)
                && life.stop_observed == CoreStop::None
                && (self.context.mode == Mode::Register || observed)
                && self
                    .result
                    .as_ref()
                    .is_some_and(|result| result.valid(binding, last_update));
        }
        if self.result.is_some() || self.reason == Reason::None {
            return false;
        }
        if self.outcome == Outcome::Unknown {
            return self.reason == Reason::CleanupUnknown && !life.settled();
        }
        if !life.settled() {
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
                && (3..=FRAME_LIMIT).contains(&bytes.len())
                && bytes[0] == b'{'
                && bytes.ends_with(b"}\n")
                && !bytes[..bytes.len() - 1]
                    .iter()
                    .any(|byte| matches!(byte, b'\r' | b'\n')),
        )?;
        self.total = self.total.checked_add(bytes.len()).ok_or_else(invalid)?;
        need(self.total <= RESPONSE_LIMIT)?;
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
                need(self.next > 0 && self.next <= MAX_EVENTS + 1)?;
                let terminal = Terminal::deserialize(envelope.payload).map_err(|_| invalid())?;
                need(terminal.valid(binding, self.last_update.as_ref(), self.observed))?;
                self.terminal = true;
                Frame::Terminal(terminal)
            }
            "observed" => {
                need(
                    self.next == 1
                        && binding.context.mode != Mode::Register
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
