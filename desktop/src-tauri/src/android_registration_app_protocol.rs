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
    Idle, Inspecting, Review, Copying, Verifying, Publishing, Settling,
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
impl Inspect {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, BridgeError> {
        let value = request(raw, &["schemaVersion", "registrationGeneration", "sourceGeneration", "context"])?;
        Ok(Self { registration_generation: counter(&value, "registrationGeneration", false)?,
            source_generation: counter(&value, "sourceGeneration", true)?,
            context: build::prepare(&value["context"]).map_err(|_| invalid())? })
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
            context: build::prepare(&value["context"]).map_err(|_| invalid())? })
    }
}
impl Cancel {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, BridgeError> {
        let value = request(raw, &["schemaVersion", "operationId", "registrationGeneration"])?;
        Ok(Self { operation_id: comparison(&value, "operationId")?,
            registration_generation: counter(&value, "registrationGeneration", true)? })
    }
}
fn context_valid(value: &Prepare) -> bool {
    serde_json::to_value(value).ok().is_some_and(|data| build::prepare(&data).is_ok_and(|copy| copy == *value))
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
        if operation.kind == Kind::Inspection && matches!(self.phase, Phase::Copying | Phase::Verifying | Phase::Publishing | Phase::Complete)
            || operation.kind == Kind::Registration && matches!(self.phase, Phase::Inspecting | Phase::Review) { return false; }
        let successful_phase = matches!(self.phase, Phase::Inspecting | Phase::Review | Phase::Copying | Phase::Verifying
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
