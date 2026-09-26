//! Closed project build-input recovery contract. Private review stamps never
//! serialize into renderer status. A terminal still needs original native joins.
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError,
    protocol::{check_value, strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-project-recovery/1";
pub(crate) const CONSENT: &str = "reviewed-project-build-input-recovery-v1";
pub(crate) const EVENT: &str = "project-recovery-state-changed";
pub(crate) const IPC_LIMIT: usize = 8192;
pub(crate) const REQUEST_LIMIT: usize = 16 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 32 * 1024;
pub(crate) const STATUS_LIMIT: usize = 32 * 1024;

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)))
}
pub(crate) fn invalid() -> BridgeError { BridgeError::new("project_recovery_invalid", "The project recovery request is invalid.") }
pub(crate) fn raw_request(bytes: &[u8]) -> Result<Value, BridgeError> {
    if !(1..=IPC_LIMIT).contains(&bytes.len()) { return Err(invalid()); }
    strict_json(bytes).map_err(|_| invalid())
}
fn sha(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Action { Inspect, Recover }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum InspectionStatus { Idle, Busy, Conflict, Pending, CleanupOnly }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Quiescence { None, Original, Operator }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Role { AndroidServices, IosServices }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observation {
    pub(crate) status: InspectionStatus, pub(crate) session: Option<String>, pub(crate) roles: Vec<Role>, pub(crate) quiescence: Quiescence,
}
impl Observation {
    pub(crate) fn eligible(&self) -> bool { self.valid() && matches!(self.status, InspectionStatus::Pending | InspectionStatus::CleanupOnly)
        && self.quiescence != Quiescence::None }
    pub(crate) fn valid(&self) -> bool {
        if self.roles.len() > 2 || !self.roles.windows(2).all(|pair| pair[0] < pair[1]) { return false; }
        match self.status {
            InspectionStatus::Idle | InspectionStatus::Busy | InspectionStatus::Conflict =>
                self.session.is_none() && self.roles.is_empty() && self.quiescence == Quiescence::None,
            InspectionStatus::Pending => self.session.as_deref().is_some_and(token),
            InspectionStatus::CleanupOnly => self.session.as_deref().is_some_and(token)
                && self.roles.is_empty() && self.quiescence != Quiescence::None,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) action: Action, pub(crate) review: Option<Observation>,
}
impl Context {
    pub(crate) fn valid(&self) -> bool { valid_id(&self.project_id) && self.draft_revision < u32::MAX
        && self.baseline_generation < u32::MAX && match self.action {
            Action::Inspect => self.review.is_none(), Action::Recover => self.review.as_ref().is_some_and(Observation::eligible),
        } }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepare {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32, pub(crate) action: Action,
}
impl Prepare {
    // Recover's review is filled ONLY from the original native settled inspection
    // under its registry lock. The renderer cannot provide a session or stamp.
    pub(crate) fn context(&self) -> Context { Context { project_id: self.project_id.clone(), draft_revision: self.draft_revision,
        baseline_generation: self.baseline_generation, action: self.action, review: None } }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start { pub(crate) operation_id: String, pub(crate) owner_generation: String, consent_version: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) owner_generation: String }
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    if !keys(value, &["projectId", "draftRevision", "baselineGeneration", "action"]) { return Err(invalid()); }
    let input = Prepare::deserialize(value).map_err(|_| invalid())?;
    if !valid_id(&input.project_id) || input.draft_revision == u32::MAX || input.baseline_generation == u32::MAX { return Err(invalid()); } Ok(input)
}
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    if !keys(value, &["operationId", "ownerGeneration", "consentVersion"]) { return Err(invalid()); }
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) || input.consent_version != CONSENT { return Err(invalid()); } Ok(input)
}
pub(crate) fn cancel(value: &Value) -> Result<Cancel, BridgeError> {
    if !keys(value, &["operationId", "ownerGeneration"]) { return Err(invalid()); }
    let input = Cancel::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) { return Err(invalid()); } Ok(input)
}
pub(crate) fn status_request(value: &Value) -> Result<(), BridgeError> { if keys(value, &[]) { Ok(()) } else { Err(invalid()) } }

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) enum Profile {
    #[serde(rename = "linux-gnu-x86_64")] LinuxX64,
    #[serde(rename = "linux-gnu-aarch64")] LinuxArm64,
    #[serde(rename = "macos-x86_64")] MacosX64,
    #[serde(rename = "macos-arm64")] MacosArm64,
}
impl Profile {
    pub(crate) fn current() -> Option<Self> {
        if cfg!(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64")) { Some(Self::LinuxX64) }
        else if cfg!(all(target_os = "linux", target_env = "gnu", target_arch = "aarch64")) { Some(Self::LinuxArm64) }
        else if cfg!(all(target_os = "macos", target_arch = "x86_64")) { Some(Self::MacosX64) }
        else if cfg!(all(target_os = "macos", target_arch = "aarch64")) { Some(Self::MacosArm64) }
        else { None }
    }
}
fn native_path(path: &Path) -> Option<&str> {
    let text = path.to_str()?;
    if text.len() > 4096 || !text.starts_with('/') || text.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}' || c == '\\' || c == ':') { return None; }
    if text != "/" {
        let mut count = 0usize;
        for part in text[1..].split('/') {
            count += 1;
            if count > 128 || part.is_empty() || part == "." || part == ".." || part.len() > 255 { return None; }
        }
    }
    Some(text)
}
pub(crate) fn request(operation: &str, generation: &str, context: &Context, profile: Profile,
    project: &RegisteredRoot, cwd: &Path, review_stamp: Option<&str>) -> Result<Vec<u8>, BridgeError> {
    if !token(operation) || !token(generation) || !context.valid() || match context.action {
        Action::Inspect => review_stamp.is_some(), Action::Recover => !review_stamp.is_some_and(sha),
    } { return Err(invalid()); }
    let identity = project.identity.posix().map_err(|_| invalid())?.preflight_identity();
    if identity.inode == "0" || identity.mode & 0o170000 != 0o040000 { return Err(invalid()); }
    let value = json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,
            "rootIdentity":identity,"cwd":native_path(cwd).ok_or_else(invalid)?,"reviewStamp":review_stamp}});
    check_value(&value).map_err(|_| invalid())?;
    let mut bytes = bounded(&value, REQUEST_LIMIT - 1).map_err(|_| invalid())?; bytes.push(b'\n'); Ok(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome { Complete, Refused, Cancelled, TimedOut, Failed, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable, IntentExpired,
    StaleIntent, ProjectChanged, ReviewStale, ManualRequired, ProjectBusy, ProjectConflict, RecoveryIncomplete,
    InputLimit, ResultLimit, CleanupUnknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Effect { NotAttempted, Inspection, RecoveryAttempted }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Limitation { BuildInputsOnlyNotStoreOrAccountRecovery, RecordedQuiescenceNotNewWorkerProof,
    ForeignChangesPreserved, CancellationDoesNotUndoCompletedCleanup, ProjectAndReleaseReadinessNotAssessed }
const LIMITATIONS: [Limitation; 5] = [Limitation::BuildInputsOnlyNotStoreOrAccountRecovery,
    Limitation::RecordedQuiescenceNotNewWorkerProof, Limitation::ForeignChangesPreserved,
    Limitation::CancellationDoesNotUndoCompletedCleanup, Limitation::ProjectAndReleaseReadinessNotAssessed];
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultData {
    schema_version: u32, scope: String, pub(crate) action: Action,
    pub(crate) observation: Option<Observation>, recovered_session: Option<String>, limitations: Vec<Limitation>,
}
impl ResultData {
    fn valid(&self, context: &Context) -> bool {
        self.schema_version == 1 && self.scope == "project-build-inputs-only" && self.action == context.action
            && self.limitations.as_slice() == LIMITATIONS && match self.action {
                Action::Inspect => self.observation.as_ref().is_some_and(Observation::valid) && self.recovered_session.is_none(),
                Action::Recover => self.observation.is_none() && self.recovered_session.as_ref().is_some_and(|session|
                    context.review.as_ref().is_some_and(|review| review.session.as_ref() == Some(session))),
            }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CoreStop { None, Cancelled, TimedOut }
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Lifetime {
    complete: bool, fatal: bool, contained: bool, command_dispatched: Option<bool>, commands: u32, profile_calls: u32,
    input_closed: bool, handlers_restored: bool, resources_closed: bool, stop_observed: CoreStop,
}
impl Lifetime {
    pub(crate) fn settled(&self) -> bool { self.complete && !self.fatal && self.contained && self.command_dispatched == Some(false)
        && self.commands == 0 && self.profile_calls == 0 && self.input_closed && self.handlers_restored && self.resources_closed }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Terminal {
    schema_version: u32, context: Context, pub(crate) outcome: Outcome, pub(crate) reason: Reason,
    pub(crate) result: Option<ResultData>, pub(crate) effect: Effect, pub(crate) review_stamp: Option<String>, pub(crate) lifetime: Lifetime,
}
impl Terminal {
    pub(crate) fn settled(&self) -> bool { self.lifetime.settled() }
    fn valid(&self, context: &Context) -> bool {
        if self.schema_version != 1 || &self.context != context || !context.valid() || self.lifetime.commands != 0
            || self.lifetime.profile_calls != 0 || self.lifetime.command_dispatched == Some(true)
            || self.effect == Effect::Inspection && context.action != Action::Inspect
            || self.effect == Effect::RecoveryAttempted && context.action != Action::Recover { return false; }
        if self.outcome == Outcome::Complete {
            let Some(result) = &self.result else { return false; };
            let needs_stamp = result.action == Action::Inspect && result.observation.as_ref().is_some_and(Observation::eligible);
            return self.reason == Reason::None && self.settled() && self.lifetime.stop_observed == CoreStop::None
                && result.valid(context) && self.effect == (if context.action == Action::Inspect { Effect::Inspection } else { Effect::RecoveryAttempted })
                && (if needs_stamp { self.review_stamp.as_deref().is_some_and(sha) } else { self.review_stamp.is_none() });
        }
        if self.result.is_some() || self.review_stamp.is_some() || self.reason == Reason::None { return false; }
        if self.outcome == Outcome::Unknown { return self.reason == Reason::CleanupUnknown && !self.settled(); }
        if !self.settled() { return false; }
        match self.outcome {
            Outcome::Cancelled => self.reason == Reason::Cancelled && self.lifetime.stop_observed == CoreStop::Cancelled,
            Outcome::TimedOut => self.reason == Reason::TimedOut && self.lifetime.stop_observed == CoreStop::TimedOut,
            Outcome::Refused | Outcome::Failed => true, _ => false,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Accepted { schema_version: u32, context: Context }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope { protocol: String, operation_id: String, owner_generation: String, sequence: u32, kind: String, payload: Value }
pub(crate) enum Frame { Accepted, Terminal(Terminal) }
fn context_keys(value: &Value) -> bool {
    keys(value, &["projectId", "draftRevision", "baselineGeneration", "action", "review"])
        && value.get("review").is_some_and(|review| review.is_null() || keys(review, &["status", "session", "roles", "quiescence"]))
}
pub(crate) fn decode(bytes: &[u8], operation: &str, generation: &str, context: &Context) -> Result<Frame, BridgeError> {
    if bytes.len() < 3 || bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") || bytes[0] != b'{'
        || bytes[bytes.len() - 2] != b'}' || bytes[..bytes.len() - 1].iter().any(|b| *b == b'\r' || *b == b'\n') { return Err(BridgeError::protocol()); }
    let value = strict_json(&bytes[..bytes.len() - 1])?;
    let envelope = Envelope::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    if envelope.protocol != PROTOCOL || envelope.operation_id != operation || envelope.owner_generation != generation
        || !token(operation) || !token(generation)
        || !envelope.payload.get("context").is_some_and(context_keys) { return Err(BridgeError::protocol()); }
    match (envelope.sequence, envelope.kind.as_str()) {
        (0, "accepted") => {
            let accepted = Accepted::deserialize(&envelope.payload).map_err(|_| BridgeError::protocol())?;
            if accepted.schema_version != 1 || &accepted.context != context || !context.valid() { return Err(BridgeError::protocol()); } Ok(Frame::Accepted)
        }
        (1, "terminal") => {
            if !keys(&envelope.payload, &["schemaVersion", "context", "outcome", "reason", "result", "effect", "reviewStamp", "lifetime"])
                || !envelope.payload.get("lifetime").is_some_and(|l| keys(l, &["complete", "fatal", "contained", "commandDispatched", "commands",
                    "profileCalls", "inputClosed", "handlersRestored", "resourcesClosed", "stopObserved"])) { return Err(BridgeError::protocol()); }
            if let Some(result) = envelope.payload.get("result").filter(|v| !v.is_null()) {
                if !keys(result, &["schemaVersion", "scope", "action", "observation", "recoveredSession", "limitations"])
                    || !result.get("observation").is_some_and(|v| v.is_null() || keys(v, &["status", "session", "roles", "quiescence"])) { return Err(BridgeError::protocol()); }
            }
            let terminal = Terminal::deserialize(&envelope.payload).map_err(|_| BridgeError::protocol())?;
            if !terminal.valid(context) { return Err(BridgeError::protocol()); } Ok(Frame::Terminal(terminal))
        }
        _ => Err(BridgeError::protocol()),
    }
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { AwaitingConsent, Starting, Running, Stopping, Terminal, Unknown }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Availability { Available, Busy, Shutdown, CleanupUnknown, DocumentLost, UnsupportedPlatform, RuntimeUnqualified }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Projection {
    pub(crate) operation_id: String, pub(crate) owner_generation: String, pub(crate) context: Context, pub(crate) phase: Phase,
    pub(crate) intent_usable: bool, pub(crate) outcome: Option<Outcome>, pub(crate) reason: Reason,
    pub(crate) result: Option<ResultData>, pub(crate) effect: Option<Effect>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status { pub(crate) schema_version: u32, pub(crate) status_revision: u32,
    pub(crate) availability: Availability, pub(crate) operation: Option<Projection> }

#[cfg(test)]
#[path = "project_recovery_protocol_tests.rs"]
pub(crate) mod tests;
