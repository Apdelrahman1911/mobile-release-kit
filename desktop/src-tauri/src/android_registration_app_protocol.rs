//! Closed app inspection/registration comparison DATA. These values contain no
//! source path, inventory, account, helper transaction or execution authority.
//! Only the existing Saved owner can publish final Review/report after its
//! actual original joins. A parsed helper terminal is never this app Status.
use serde::Serialize;
use serde_json::Value;
use crate::{
    android_build_protocol::{self as build, Availability, Prepare},
    android_tool_sources::Role, edit_protocol::token, error::BridgeError,
};

pub(crate) const EVENT: &str = "android-tool-registration-state-changed";
pub(crate) const CONSENT: &str = "android-tool-protected-copy-v1";
pub(crate) const SERVICE_EVENT: &str = "android-tool-service-state-changed";
pub(crate) const SERVICE_CONSENT: &str = "android-tool-service-registration-v1";
pub(crate) const REQUEST_LIMIT: usize = 8192;
pub(crate) const STATUS_LIMIT: usize = 65536;
pub(crate) const WORK_SECONDS: u64 = 300;
pub(crate) const FINALITY_SECONDS: u64 = 310;
pub(crate) const REVIEW_SECONDS: u64 = 300;
const COUNTER_MAX: u32 = u32::MAX - 1;
const SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
const SOURCE_FILES: u32 = 16384;
const SOURCE_ENTRIES: u32 = 32768;
const SOURCE_ALIASES: u32 = 128;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Prerequisite {
    Ready, SupplierUnavailable, SigningUnavailable, ApprovalRequired,
    ApprovalDenied, ServiceUnavailable, FreshServiceUnavailable,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind { Inspection, Registration }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Idle, Inspecting, Review, Preparing, Copying, Verifying, Publishing, Settling,
    Stopping, Complete, Refused, Cancelled, Unknown,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, NotInspected, Cancelled, ContextChanged, SourceChanged, SourceRefused,
    VersionMismatch, LayoutRefused, SupplierUnavailable, SigningUnavailable,
    ApprovalRequired, ApprovalDenied, ServiceUnavailable, FreshServiceUnavailable,
    ReviewExpired, StaleReview, TimedOut, DocumentLost, Shutdown, Busy,
    InputLimit, ResultLimit, ProtocolError, RegistrationRefused, CleanupUnknown,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operation {
    pub(crate) operation_id: String, pub(crate) registration_generation: u32,
    pub(crate) source_generation: u32, pub(crate) kind: Kind, pub(crate) context: Prepare,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Compatibility { Compatible, Refused, Unavailable }
/// Picked-role observations only, not the private whole-copy census. Fixed app
/// support originals also consume the same native byte/entry/memory budgets.
/// A refusal can report observed subtotals; complete=false never means that
/// omitted input has size zero.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Source {
    pub(crate) role: Role, pub(crate) version: Option<String>,
    pub(crate) logical_bytes: u32, pub(crate) files: u32, pub(crate) entries: u32,
    pub(crate) aliases: u32, pub(crate) complete: bool, pub(crate) compatibility: Compatibility,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Review {
    pub(crate) review_id: String, pub(crate) source_generation: u32,
    pub(crate) context: Prepare, pub(crate) consent_version: &'static str,
    pub(crate) license_acknowledgment_required: bool, pub(crate) sources: Vec<Source>,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProtectedCopy { NotCreated, Published, RetainedPartial }
/// Decimal strings preserve the helper's complete u64 observation range.
/// These fields are not paths, handles, permits or a complete-output assertion.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Accounting {
    pub(crate) written_bytes: String, pub(crate) observed_logical_bytes: String,
    pub(crate) observed_allocated_bytes: String, pub(crate) complete: bool,
    pub(crate) content_files: u32, pub(crate) content_aliases: u32,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Problem {
    Binding, Bounds, SupplierUnavailable, Inventory, Ownership, Collision,
    Native, Stopped, Unknown, Transfer, Persist, Admission, Unavailable,
}
/// A prefix of the recorded bounded errors, not a census of all possible errors.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Problems {
    pub(crate) recorded: u32, pub(crate) shown: u32, pub(crate) omitted: u32,
    pub(crate) first: Option<Problem>, pub(crate) items: Vec<Problem>,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Report {
    pub(crate) sources: Vec<Source>, pub(crate) protected_copy: ProtectedCopy,
    pub(crate) accounting: Option<Accounting>, pub(crate) problems: Problems,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32, pub(crate) status_revision: u32,
    pub(crate) registration_generation: u32, pub(crate) availability: Availability,
    pub(crate) prerequisite: Prerequisite, pub(crate) phase: Phase, pub(crate) reason: Reason,
    pub(crate) operation: Option<Operation>, pub(crate) review: Option<Review>,
    pub(crate) report: Option<Report>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Inspect {
    pub(crate) registration_generation: u32, pub(crate) source_generation: u32,
    pub(crate) context: Prepare,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Register {
    pub(crate) registration_generation: u32, pub(crate) source_generation: u32,
    pub(crate) review_id: String, pub(crate) context: Prepare,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cancel {
    pub(crate) operation_id: String, pub(crate) registration_generation: u32,
}

/// Service setup is a separate original action and consent. A completed
/// observation is prerequisite DATA only: it cannot authorize payload transfer,
/// infer user approval, replace authentication, or create the peer's Ready.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ServiceAction { Check, RequestRegistration, OpenApprovalSettings }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ServicePhase { Idle, Checking, Requesting, OpeningSettings, Settling, Stopping, Complete, Refused, Cancelled, Unknown }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ServiceState { NotRegistered, Enabled, RequiresApproval, NotFound, Unavailable, Error }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ServiceOutcome {
    NotEntered, Observed, RegistrationRequested, AlreadyRegistered, NeedsApproval,
    SettingsRequested, DeniedByUser, Stopped, Refused, Error, Unknown,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServiceOperation {
    pub(crate) operation_id: String, pub(crate) setup_generation: u32,
    pub(crate) source_generation: u32, pub(crate) action: ServiceAction,
    pub(crate) context: Prepare,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServiceObservation {
    pub(crate) state: ServiceState, pub(crate) outcome: ServiceOutcome,
    pub(crate) mutation_entered: bool, pub(crate) mutation_returned: bool,
    pub(crate) mutation_uncertain: bool, pub(crate) native_settled: bool,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServiceStatus {
    pub(crate) schema_version: u32, pub(crate) status_revision: u32,
    pub(crate) setup_generation: u32, pub(crate) availability: Availability,
    pub(crate) prerequisite: Prerequisite, pub(crate) phase: ServicePhase,
    pub(crate) reason: Reason, pub(crate) operation: Option<ServiceOperation>,
    pub(crate) observation: Option<ServiceObservation>,
}
/// The route supplies action. No renderer-supplied method, service name, path,
/// requirement, deadline, system URL or automatic-registration option exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceRequest {
    pub(crate) setup_generation: u32, pub(crate) context: Prepare,
    pub(crate) action: ServiceAction,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceCancel {
    pub(crate) operation_id: String, pub(crate) setup_generation: u32,
}
pub(crate) fn service_invalid() -> BridgeError {
    BridgeError::new("android_service_invalid", "The service request was rejected before admission. Nothing was authorized.")
}
pub(crate) fn service_unavailable() -> BridgeError {
    BridgeError::new("android_service_unavailable", "The fixed Android service action was not admitted. Check its status and prerequisites.")
}
pub(crate) fn service_unconfirmed() -> BridgeError {
    BridgeError::new("android_service_unconfirmed", "The original service action is unconfirmed. Keep its Status and Cancel; do not repeat registration.")
}
/// Rejection BEFORE any new original is admitted. Never use for lost GO, an
/// admitted worker failure, or a Status/Cancel response for an existing original.
pub(crate) fn invalid() -> BridgeError {
    BridgeError::new("android_registration_invalid", "The source-review request was rejected before admission. Nothing was authorized.")
}
/// Rejection BEFORE original admission only; an admitted error is unconfirmed.
pub(crate) fn unavailable() -> BridgeError {
    BridgeError::new("android_registration_unavailable", "Protected Android tool registration was not admitted. Check prerequisites and original Status.")
}
pub(crate) fn unconfirmed() -> BridgeError {
    BridgeError::new("android_registration_unconfirmed", "The original source inspection or registration reply is unconfirmed. Keep its Status and Cancel; do not repeat copy.")
}
fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == names.len()
        && names.iter().all(|name| object.contains_key(*name)))
}
fn request(raw: &[u8], names: &[&str]) -> Result<Value, BridgeError> {
    let value = build::strict_data(raw, REQUEST_LIMIT, false).map_err(|_| invalid())?;
    if !keys(&value, names) || value["schemaVersion"].as_u64() != Some(1) { return Err(invalid()); }
    Ok(value)
}
fn counter(value: &Value, name: &str, positive: bool) -> Result<u32, BridgeError> {
    let count = value[name].as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(invalid)?;
    if count > COUNTER_MAX || positive && count == 0 { Err(invalid()) } else { Ok(count) }
}
fn comparison(value: &Value, name: &str) -> Result<String, BridgeError> {
    value[name].as_str().filter(|text| token(text)).map(str::to_owned).ok_or_else(invalid)
}
pub(crate) fn status_request(raw: &[u8]) -> Result<(), BridgeError> {
    request(raw, &["schemaVersion"]).map(|_| ())
}
// Tool inspection, protected copying and service setup share saved-input
// comparison data, but never signing assignments or a signed-build intent.
fn unsigned_registration_context(value: &Value) -> Result<Prepare, BridgeError> {
    let input = build::prepare(value).map_err(|_| invalid())?;
    if input.signing.is_some() { return Err(invalid()); }
    Ok(input)
}
impl Inspect {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, BridgeError> {
        let value = request(raw, &["schemaVersion", "registrationGeneration", "sourceGeneration", "context"])?;
        Ok(Self { registration_generation: counter(&value, "registrationGeneration", false)?,
            source_generation: counter(&value, "sourceGeneration", true)?,
            context: unsigned_registration_context(&value["context"]).map_err(|_| invalid())? })
    }
}
impl Register {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, BridgeError> {
        let value = request(raw, &["schemaVersion", "registrationGeneration", "sourceGeneration", "reviewId",
            "context", "consentVersion", "licenseAcknowledged"])?;
        if value["consentVersion"].as_str() != Some(CONSENT) || value["licenseAcknowledged"].as_bool() != Some(true) {
            return Err(invalid());
        }
        Ok(Self { registration_generation: counter(&value, "registrationGeneration", true)?,
            source_generation: counter(&value, "sourceGeneration", true)?, review_id: comparison(&value, "reviewId")?,
            context: unsigned_registration_context(&value["context"]).map_err(|_| invalid())? })
    }
}
impl Cancel {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, BridgeError> {
        let value = request(raw, &["schemaVersion", "operationId", "registrationGeneration"])?;
        Ok(Self { operation_id: comparison(&value, "operationId")?,
            registration_generation: counter(&value, "registrationGeneration", true)? })
    }
}
impl ServiceRequest {
    fn parse_action(raw: &[u8], action: ServiceAction) -> Result<Self, BridgeError> {
        let names: &[&str] = if action == ServiceAction::RequestRegistration {
            &["schemaVersion", "setupGeneration", "context", "consentVersion", "registrationAcknowledged"]
        } else { &["schemaVersion", "setupGeneration", "context"] };
        let value = request(raw, names).map_err(|_| service_invalid())?;
        if action == ServiceAction::RequestRegistration &&
            (value["consentVersion"].as_str() != Some(SERVICE_CONSENT)
                || value["registrationAcknowledged"].as_bool() != Some(true)) { return Err(service_invalid()); }
        Ok(Self { setup_generation: counter(&value, "setupGeneration", false).map_err(|_| service_invalid())?,
            context: unsigned_registration_context(&value["context"]).map_err(|_| service_invalid())?, action })
    }
    pub(crate) fn check(raw: &[u8]) -> Result<Self, BridgeError> { Self::parse_action(raw, ServiceAction::Check) }
    pub(crate) fn request_registration(raw: &[u8]) -> Result<Self, BridgeError> { Self::parse_action(raw, ServiceAction::RequestRegistration) }
    pub(crate) fn open_approval_settings(raw: &[u8]) -> Result<Self, BridgeError> { Self::parse_action(raw, ServiceAction::OpenApprovalSettings) }
}
impl ServiceCancel {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, BridgeError> {
        let value = request(raw, &["schemaVersion", "operationId", "setupGeneration"]).map_err(|_| service_invalid())?;
        Ok(Self { operation_id: comparison(&value, "operationId").map_err(|_| service_invalid())?,
            setup_generation: counter(&value, "setupGeneration", true).map_err(|_| service_invalid())? })
    }
}
impl ServiceObservation {
    fn valid(&self, action: ServiceAction) -> bool {
        if self.mutation_returned && !self.mutation_entered
            || self.mutation_uncertain && (!self.mutation_entered || self.mutation_returned)
            || self.native_settled && (self.mutation_uncertain || self.outcome == ServiceOutcome::Unknown)
            || action == ServiceAction::Check && (self.mutation_entered || self.mutation_returned || self.mutation_uncertain) { return false; }
        match self.outcome {
            ServiceOutcome::Observed => action == ServiceAction::Check,
            ServiceOutcome::RegistrationRequested | ServiceOutcome::DeniedByUser =>
                action == ServiceAction::RequestRegistration && self.mutation_returned,
            ServiceOutcome::AlreadyRegistered | ServiceOutcome::NeedsApproval => action == ServiceAction::RequestRegistration,
            ServiceOutcome::SettingsRequested => action == ServiceAction::OpenApprovalSettings && self.mutation_returned,
            _ => true,
        }
    }
}
impl ServiceStatus {
    pub(crate) fn valid(&self) -> bool {
        if self.schema_version != 1 || self.status_revision > COUNTER_MAX || self.setup_generation > COUNTER_MAX { return false; }
        let Some(operation) = &self.operation else {
            return self.setup_generation == 0 && self.phase == ServicePhase::Idle && self.observation.is_none()
                && matches!(self.reason, Reason::SigningUnavailable | Reason::ServiceUnavailable);
        };
        if self.setup_generation == 0 || operation.setup_generation != self.setup_generation
            || !token(&operation.operation_id) || operation.source_generation > COUNTER_MAX
            || !context_valid(&operation.context) || self.phase == ServicePhase::Idle { return false; }
        if self.phase == ServicePhase::Checking && operation.action != ServiceAction::Check
            || self.phase == ServicePhase::Requesting && operation.action != ServiceAction::RequestRegistration
            || self.phase == ServicePhase::OpeningSettings && operation.action != ServiceAction::OpenApprovalSettings { return false; }
        if matches!(self.phase, ServicePhase::Checking | ServicePhase::Requesting | ServicePhase::OpeningSettings
            | ServicePhase::Settling | ServicePhase::Complete) && self.reason != Reason::None
            || matches!(self.phase, ServicePhase::Stopping | ServicePhase::Refused) && matches!(self.reason, Reason::None | Reason::NotInspected)
            || self.phase == ServicePhase::Cancelled && self.reason != Reason::Cancelled
            || self.phase == ServicePhase::Unknown && (self.reason != Reason::CleanupUnknown || self.availability != Availability::CleanupUnknown) { return false; }
        if let Some(observation) = &self.observation {
            if !observation.valid(operation.action)
                || !matches!(self.phase, ServicePhase::Complete | ServicePhase::Refused | ServicePhase::Cancelled)
                || !observation.native_settled { return false; }
            // Earlier accepted cancellation/deadline remains the terminal
            // reason even if a later real returned mutation reports denial.
            // The observation preserves denial independently, never inferred
            // from RequiresApproval or used to overwrite the first failure.
            if observation.outcome == ServiceOutcome::DeniedByUser &&
                (!matches!(self.phase, ServicePhase::Refused | ServicePhase::Cancelled)
                    || matches!(self.reason, Reason::None | Reason::NotInspected)
                    || self.prerequisite != Prerequisite::ApprovalDenied) { return false; }
        }
        if self.phase == ServicePhase::Complete && !self.observation.is_some_and(|observation|
            matches!(observation.outcome, ServiceOutcome::Observed | ServiceOutcome::RegistrationRequested
                | ServiceOutcome::AlreadyRegistered | ServiceOutcome::NeedsApproval | ServiceOutcome::SettingsRequested)) { return false; }
        true
    }
    pub(crate) fn bounded(self) -> Result<Self, BridgeError> {
        if !self.valid() || !serde_json::to_vec(&self).is_ok_and(|bytes| bytes.len() <= STATUS_LIMIT) { return Err(service_unconfirmed()); }
        Ok(self)
    }
}
fn context_valid(value: &Prepare) -> bool {
    serde_json::to_value(value).ok().is_some_and(|data|
        unsigned_registration_context(&data).is_ok_and(|copy| copy == *value))
}
fn version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".+_-".contains(&byte))
}
fn sources_valid(sources: &[Source], review: bool) -> bool {
    let roles = [Role::Jdk, Role::Sdk, Role::Gradle];
    if sources.len() > 3 || review && sources.len() != 3 { return false; }
    let (mut bytes, mut files, mut entries, mut aliases) = (0_u64, 0_u64, 0_u64, 0_u64);
    let mut previous = None;
    for source in sources {
        let Some(index) = roles.iter().position(|role| *role == source.role) else { return false; };
        if previous.is_some_and(|before| before >= index)
            || source.version.as_ref().is_some_and(|value| !version(value))
            || source.logical_bytes as u64 > SOURCE_BYTES || source.files > SOURCE_FILES
            || source.entries > SOURCE_ENTRIES || source.aliases > SOURCE_ALIASES
            || source.files + source.aliases > source.entries
            || review && (!source.complete || source.compatibility != Compatibility::Compatible
                || source.version.is_none() || source.files == 0) { return false; }
        previous = Some(index);
        bytes += source.logical_bytes as u64; files += source.files as u64;
        entries += source.entries as u64; aliases += source.aliases as u64;
    }
    bytes <= SOURCE_BYTES && files <= SOURCE_FILES as u64 && entries <= SOURCE_ENTRIES as u64
        && aliases <= SOURCE_ALIASES as u64
}
fn decimal(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20
        && value.parse::<u64>().is_ok_and(|number| number.to_string() == value)
}
impl Accounting {
    fn valid(&self) -> bool {
        decimal(&self.written_bytes) && decimal(&self.observed_logical_bytes) && decimal(&self.observed_allocated_bytes)
            && self.content_files <= SOURCE_FILES && self.content_aliases <= SOURCE_FILES
    }
}
impl Problems {
    fn valid(&self) -> bool {
        self.recorded <= 64 && self.shown == self.recorded.min(20) && self.shown as usize == self.items.len()
            && self.omitted == self.recorded - self.shown && self.first == self.items.first().copied()
    }
}
impl Report {
    fn valid(&self, kind: Kind) -> bool {
        sources_valid(&self.sources, false) && self.problems.valid()
            && self.accounting.as_ref().is_none_or(Accounting::valid)
            && (kind != Kind::Inspection || self.protected_copy == ProtectedCopy::NotCreated && self.accounting.is_none())
    }
}
impl Status {
    /// DATA-only coherence, not a native-finality validator. Owner publication
    /// still requires the genuine same-original worker/coordinator/close facts.
    pub(crate) fn valid(&self) -> bool {
        if self.schema_version != 1 || self.status_revision > COUNTER_MAX || self.registration_generation > COUNTER_MAX
            || self.availability == Availability::Available && self.prerequisite != Prerequisite::Ready { return false; }
        let Some(operation) = &self.operation else {
            return self.registration_generation == 0 && self.phase == Phase::Idle && self.review.is_none() && self.report.is_none()
                && matches!(self.reason, Reason::NotInspected | Reason::SupplierUnavailable | Reason::SigningUnavailable
                    | Reason::ApprovalRequired | Reason::ApprovalDenied | Reason::ServiceUnavailable | Reason::FreshServiceUnavailable);
        };
        if self.registration_generation == 0 || operation.registration_generation != self.registration_generation
            || !token(&operation.operation_id) || operation.source_generation == 0 || operation.source_generation > COUNTER_MAX
            || !context_valid(&operation.context) || self.phase == Phase::Idle { return false; }
        if operation.kind == Kind::Inspection && matches!(self.phase, Phase::Preparing | Phase::Copying | Phase::Verifying | Phase::Publishing | Phase::Complete)
            || operation.kind == Kind::Registration && matches!(self.phase, Phase::Inspecting | Phase::Review) { return false; }
        let successful_phase = matches!(self.phase, Phase::Inspecting | Phase::Review | Phase::Preparing | Phase::Copying | Phase::Verifying
            | Phase::Publishing | Phase::Settling | Phase::Complete);
        if self.phase == Phase::Unknown && self.availability != Availability::CleanupUnknown
            || successful_phase && self.reason != Reason::None
            || self.phase == Phase::Unknown && self.reason != Reason::CleanupUnknown
            || self.phase == Phase::Cancelled && self.reason != Reason::Cancelled
            || matches!(self.phase, Phase::Stopping | Phase::Refused) && matches!(self.reason, Reason::None | Reason::NotInspected)
            || !matches!(self.phase, Phase::Complete | Phase::Refused | Phase::Cancelled) && self.report.is_some() { return false; }
        if self.phase == Phase::Review {
            let Some(review) = &self.review else { return false; };
            if self.availability != Availability::Available || self.prerequisite != Prerequisite::Ready
                || !token(&review.review_id) || review.source_generation != operation.source_generation
                || review.context != operation.context || review.consent_version != CONSENT
                || !review.license_acknowledgment_required || !sources_valid(&review.sources, true) { return false; }
        } else if self.review.is_some() { return false; }
        if let Some(report) = &self.report {
            if !report.valid(operation.kind) { return false; }
        }
        if self.phase == Phase::Complete {
            let Some(report) = &self.report else { return false; };
            if report.protected_copy != ProtectedCopy::Published || !sources_valid(&report.sources, true)
                || !report.accounting.as_ref().is_some_and(|data| data.complete)
                || report.problems.recorded != 0 { return false; }
        }
        true
    }
    pub(crate) fn bounded(self) -> Result<Self, BridgeError> {
        if !self.valid() || !serde_json::to_vec(&self).is_ok_and(|bytes| bytes.len() <= STATUS_LIMIT) {
            return Err(unconfirmed());
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context_data() -> Value {
        serde_json::json!({"projectId":"project-a","draftRevision":0,"baselineGeneration":1,
            "savedConfig":{"bytes":1,"sha256":"a".repeat(64)},
            "savedVersion":{"source":"VERSION","bytes":1,"sha256":"b".repeat(64),"name":"1.0","build":1},
            "artifactValidation":{"mode":"structure-and-version","uploadCertificateSha256":null}})
    }
    fn inspect_data() -> Value {
        serde_json::json!({"schemaVersion":1,"registrationGeneration":0,"sourceGeneration":3,"context":context_data()})
    }
    fn source(role: Role) -> Source {
        Source { role, version: Some("17.0.1".into()), logical_bytes: 1, files: 1, entries: 1,
            aliases: 0, complete: true, compatibility: Compatibility::Compatible }
    }
    fn review_status() -> Status {
        let context = build::prepare(&context_data()).unwrap();
        Status { schema_version: 1, status_revision: 2, registration_generation: 1, availability: Availability::Available,
            prerequisite: Prerequisite::Ready, phase: Phase::Review, reason: Reason::None,
            operation: Some(Operation { operation_id: "a".repeat(32), registration_generation: 1, source_generation: 3,
                kind: Kind::Inspection, context: context.clone() }),
            review: Some(Review { review_id: "b".repeat(32), source_generation: 3, context, consent_version: CONSENT,
                license_acknowledgment_required: true, sources: vec![source(Role::Jdk), source(Role::Sdk), source(Role::Gradle)] }),
            report: None }
    }
    #[test]
    fn requests_are_closed_comparisons_with_the_existing_saved_context_contract() {
        let good = inspect_data();
        assert!(Inspect::parse(&serde_json::to_vec(&good).unwrap()).is_ok());
        for (key, value) in [("path", serde_json::json!("/private/source")), ("uid", serde_json::json!(501)),
            ("deadline", serde_json::json!(300)), ("qualified", serde_json::json!(true)),
            ("sourceGeneration", serde_json::json!(0)), ("registrationGeneration", serde_json::json!(u32::MAX))] {
            let mut bad = good.clone(); bad[key] = value;
            assert!(Inspect::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let mut bad = good; bad["context"]["savedVersion"]["bytes"] = serde_json::json!(0);
        assert!(Inspect::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        assert!(status_request(br#"{"schemaVersion":1}"#).is_ok());
        assert!(status_request(br#"{"schemaVersion":1,"schemaVersion":1}"#).is_err());
        assert!(status_request(br#"{"schemaVersion":1.0}"#).is_err());
        assert!(status_request(br#"{}"#).is_err());
    }
    #[test]
    fn source_copy_and_service_setup_do_not_admit_signed_build_contexts() {
        fn admission<T>(result: Result<T, BridgeError>, allowed: bool, code: &str, label: &str) {
            match result {
                Ok(_) => assert!(allowed, "signed context admitted: {label}"),
                Err(error) => {
                    assert!(!allowed, "unsigned context refused: {label}");
                    assert_eq!(error.code, code, "wrong pre-admission error: {label}");
                }
            }
        }
        let build = crate::android_build_protocol::tests::signed_context();
        let mut signature = context_data();
        signature["artifactValidation"] = serde_json::json!(build.artifact_validation);
        let mut signed = signature.clone();
        signed["signing"] = serde_json::json!(build.signing.unwrap());
        // The ordinary build owner still supports a valid local signing request.
        let prepare = crate::android_build_protocol::prepare(&signed).unwrap();
        assert!(prepare.context().signed());
        assert!(!context_valid(&prepare));
        let mut null_signing = signature.clone();
        null_signing["signing"] = Value::Null;
        for (label, context, allowed) in [("structure", context_data(), true),
            ("signature inspection", signature, true), ("local signing", signed, false),
            ("explicit null signing", null_signing, false)] {
            let inspect = serde_json::json!({"schemaVersion":1,"registrationGeneration":0,
                "sourceGeneration":3,"context":context.clone()});
            let register = serde_json::json!({"schemaVersion":1,"registrationGeneration":1,"sourceGeneration":3,
                "reviewId":"a".repeat(32),"context":context.clone(),"consentVersion":CONSENT,"licenseAcknowledged":true});
            let service = serde_json::json!({"schemaVersion":1,"setupGeneration":0,"context":context.clone()});
            let service_registration = serde_json::json!({"schemaVersion":1,"setupGeneration":0,"context":context.clone(),
                "consentVersion":SERVICE_CONSENT,"registrationAcknowledged":true});
            admission(Inspect::parse(&serde_json::to_vec(&inspect).unwrap()), allowed,
                "android_registration_invalid", label);
            admission(Register::parse(&serde_json::to_vec(&register).unwrap()), allowed,
                "android_registration_invalid", label);
            let service_bytes = serde_json::to_vec(&service).unwrap();
            admission(ServiceRequest::check(&service_bytes), allowed, "android_service_invalid", label);
            admission(ServiceRequest::open_approval_settings(&service_bytes), allowed, "android_service_invalid", label);
            admission(ServiceRequest::request_registration(&serde_json::to_vec(&service_registration).unwrap()),
                allowed, "android_service_invalid", label);
            if let Ok(prepare) = crate::android_build_protocol::prepare(&context) {
                assert_eq!(context_valid(&prepare), allowed, "request/status domain drift: {label}");
            }
        }
    }
    #[test]
    fn register_requires_current_review_comparisons_fixed_consent_and_explicit_true() {
        let good = serde_json::json!({"schemaVersion":1,"registrationGeneration":1,"sourceGeneration":3,
            "reviewId":"a".repeat(32),"context":context_data(),"consentVersion":CONSENT,"licenseAcknowledged":true});
        assert!(Register::parse(&serde_json::to_vec(&good).unwrap()).is_ok());
        for (key, value) in [("licenseAcknowledged", serde_json::json!(false)), ("licenseAcknowledged", Value::Null),
            ("consentVersion", serde_json::json!("automatic")), ("reviewId", serde_json::json!("renderer-path")),
            ("registrationGeneration", serde_json::json!(0)), ("approval", serde_json::json!(true))] {
            let mut bad = good.clone(); bad[key] = value;
            assert!(Register::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        assert!(Cancel::parse(br#"{"schemaVersion":1,"operationId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","registrationGeneration":1}"#).is_ok());
        assert!(Cancel::parse(br#"{"schemaVersion":1,"operationId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","registrationGeneration":0}"#).is_err());
    }
    #[test]
    fn service_routes_are_closed_and_registration_has_its_own_explicit_consent() {
        let check = serde_json::json!({"schemaVersion":1,"setupGeneration":0,"context":context_data()});
        assert_eq!(ServiceRequest::check(&serde_json::to_vec(&check).unwrap()).unwrap().action, ServiceAction::Check);
        assert_eq!(ServiceRequest::open_approval_settings(&serde_json::to_vec(&check).unwrap()).unwrap().action,
            ServiceAction::OpenApprovalSettings);
        assert!(ServiceRequest::request_registration(&serde_json::to_vec(&check).unwrap()).is_err());
        let mut register = check.clone();
        register["consentVersion"] = serde_json::json!(SERVICE_CONSENT);
        register["registrationAcknowledged"] = serde_json::json!(true);
        assert_eq!(ServiceRequest::request_registration(&serde_json::to_vec(&register).unwrap()).unwrap().action,
            ServiceAction::RequestRegistration);
        assert!(ServiceRequest::check(&serde_json::to_vec(&register).unwrap()).is_err());
        for (key,value) in [("registrationAcknowledged",serde_json::json!(false)),("registrationAcknowledged",serde_json::json!("true")),
            ("consentVersion",serde_json::json!(CONSENT)),("licenseAcknowledged",serde_json::json!(true)),
            ("path",serde_json::json!("/tmp/service")),("teamId",serde_json::json!("ABCDEFGHIJ")),
            ("serviceName",serde_json::json!("alternate")),("url",serde_json::json!("https://example.invalid")),
            ("setupGeneration",serde_json::json!(u32::MAX))] {
            let mut bad=register.clone();bad[key]=value;
            assert!(ServiceRequest::request_registration(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        assert!(ServiceCancel::parse(br#"{"schemaVersion":1,"operationId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","setupGeneration":1}"#).is_ok());
        assert!(ServiceCancel::parse(br#"{"schemaVersion":1,"operationId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","registrationGeneration":1}"#).is_err());
        assert!(ServiceCancel::parse(br#"{"schemaVersion":1,"operationId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","setupGeneration":0}"#).is_err());
    }
    #[test]
    fn service_observation_preserves_denial_without_inferring_approval_or_peer_ready() {
        let operation=ServiceOperation {operation_id:"c".repeat(32),setup_generation:1,source_generation:0,
            action:ServiceAction::Check,context:build::prepare(&context_data()).unwrap()};
        let mut status=ServiceStatus {schema_version:1,status_revision:1,setup_generation:1,
            availability:Availability::Available,prerequisite:Prerequisite::ApprovalRequired,
            phase:ServicePhase::Complete,reason:Reason::None,operation:Some(operation),
            observation:Some(ServiceObservation {state:ServiceState::RequiresApproval,outcome:ServiceOutcome::Observed,
                mutation_entered:false,mutation_returned:false,mutation_uncertain:false,native_settled:true})};
        // Setup can finish correctly while native approval is still required.
        assert!(status.valid());
        status.operation.as_mut().unwrap().action=ServiceAction::RequestRegistration;
        let observation=status.observation.as_mut().unwrap();
        observation.outcome=ServiceOutcome::DeniedByUser;observation.mutation_entered=true;observation.mutation_returned=true;
        assert!(!status.valid());
        status.phase=ServicePhase::Refused;status.reason=Reason::ApprovalDenied;status.prerequisite=Prerequisite::ApprovalDenied;
        assert!(status.valid());
        status.phase=ServicePhase::Cancelled;status.reason=Reason::Cancelled;assert!(status.valid());
        status.phase=ServicePhase::Refused;status.reason=Reason::TimedOut;assert!(status.valid());
        status.prerequisite=Prerequisite::ApprovalRequired;assert!(!status.valid());
        status.prerequisite=Prerequisite::ApprovalDenied;
        status.observation.as_mut().unwrap().mutation_returned=false;assert!(!status.valid());
        status.observation.as_mut().unwrap().mutation_returned=true;
        status.observation.as_mut().unwrap().native_settled=false;assert!(!status.valid());
        status.observation=None;status.phase=ServicePhase::Unknown;status.reason=Reason::CleanupUnknown;
        status.availability=Availability::CleanupUnknown;assert!(status.valid());
        status.observation=Some(ServiceObservation {state:ServiceState::Enabled,outcome:ServiceOutcome::AlreadyRegistered,
            mutation_entered:false,mutation_returned:false,mutation_uncertain:false,native_settled:true});
        assert!(!status.valid()); // Known-looking callback DATA cannot rewrite Unknown finality.
    }
    #[test]
    fn usable_review_requires_all_complete_roles_same_inputs_and_ready_prerequisites() {
        let good = review_status();
        assert!(good.valid());
        let mut missing = good.clone(); missing.prerequisite = Prerequisite::SupplierUnavailable;
        assert!(!missing.valid());
        let mut incomplete = good.clone(); incomplete.review.as_mut().unwrap().sources[0].complete = false;
        assert!(!incomplete.valid());
        let mut drift = good.clone(); drift.review.as_mut().unwrap().context.draft_revision += 1;
        assert!(!drift.valid());
        let mut stopped = good.clone(); stopped.phase = Phase::Unknown; stopped.reason = Reason::CleanupUnknown;
        stopped.availability = Availability::CleanupUnknown;
        assert!(!stopped.valid());
        stopped.review = None; assert!(stopped.valid());
        let mut partial = good; partial.review.as_mut().unwrap().sources.pop();
        assert!(!partial.valid());
    }
    #[test]
    fn output_accounting_is_exact_u64_data_and_errors_are_only_the_recorded_prefix() {
        let mut counts = Accounting { written_bytes: u64::MAX.to_string(), observed_logical_bytes: "0".into(),
            observed_allocated_bytes: "9007199254740993".into(), complete: false, content_files: 1, content_aliases: 0 };
        assert!(counts.valid());
        for value in ["18446744073709551616", "-1", "00", "1e3", "1.0", " 1"] {
            counts.written_bytes = value.into(); assert!(!counts.valid());
        }
        let mut errors = Problems { recorded: 64, shown: 20, omitted: 44, first: Some(Problem::Bounds),
            items: vec![Problem::Bounds; 20] };
        assert!(errors.valid());
        errors.omitted = 0; assert!(!errors.valid());
        errors.omitted = 44; errors.items.pop(); assert!(!errors.valid());
    }
}
