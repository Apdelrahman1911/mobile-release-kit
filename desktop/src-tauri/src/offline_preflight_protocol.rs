//! Closed saved-input comparison, consent and redacted result DATA.
//! A core terminal is provisional until this operation's original native joins.
use std::{collections::BTreeMap, path::Path};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError,
    protocol::{check_value, strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-offline-preflight/1";
pub(crate) const CONSENT: &str = "saved-offline-android-v1";
pub(crate) const EVENT: &str = "offline-preflight-state-changed";
pub(crate) const IPC_LIMIT: usize = 8192;
pub(crate) const REQUEST_LIMIT: usize = 16 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024; // Both frames, framing and rejected drain bytes.
pub(crate) const STATUS_LIMIT: usize = 64 * 1024;

fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)))
}
pub(crate) fn invalid() -> BridgeError { BridgeError::new("offline_preflight_invalid", "The saved offline-check request is invalid.") }
/// Called only on original InvokeBody::Raw bytes; never a reserialized Value.
pub(crate) fn raw_request(bytes: &[u8]) -> Result<Value, BridgeError> {
    if !(1..=IPC_LIMIT).contains(&bytes.len()) { return Err(invalid()); }
    strict_json(bytes).map_err(|_| invalid())
}
fn sha(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Content { pub(crate) bytes: u32, pub(crate) sha256: String }
impl Content { fn valid(&self) -> bool { (1..=524288).contains(&self.bytes) && sha(&self.sha256) } }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform { Android }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation { OfflinePreflight }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) platform: Platform, pub(crate) operation: Operation,
}
impl Context {
    fn valid(&self) -> bool { valid_id(&self.project_id) && self.draft_revision < u32::MAX
        && self.baseline_generation < u32::MAX && self.saved_config.valid() }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepare {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content,
}
impl Prepare {
    pub(crate) fn context(&self) -> Context { Context { project_id: self.project_id.clone(), draft_revision: self.draft_revision,
        baseline_generation: self.baseline_generation, saved_config: self.saved_config.clone(),
        platform: Platform::Android, operation: Operation::OfflinePreflight } }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start { pub(crate) operation_id: String, pub(crate) owner_generation: String, consent_version: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) owner_generation: String }
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    if !keys(value, &["projectId", "draftRevision", "baselineGeneration", "savedConfig"]) { return Err(invalid()); }
    let input = Prepare::deserialize(value).map_err(|_| invalid())?;
    if !input.context().valid() { return Err(invalid()); } Ok(input)
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
#[derive(Serialize)]
pub(crate) struct RootIdentity {
    pub(crate) device: String, pub(crate) inode: String, pub(crate) mode: u32, pub(crate) uid: u32, pub(crate) gid: u32,
}
fn decimal(value: &str) -> bool { !value.is_empty() && (value == "0" || !value.starts_with('0'))
    && value.bytes().all(|b| b.is_ascii_digit()) && value.parse::<u64>().is_ok() }
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
    project: &RegisteredRoot, cwd: &Path) -> Result<Vec<u8>, BridgeError> {
    if !token(operation) || !token(generation) || !context.valid() { return Err(invalid()); }
    let identity = project.identity.posix().map_err(|_| invalid())?.preflight_identity();
    if !decimal(&identity.device) || !decimal(&identity.inode) || identity.inode == "0" || identity.mode & 0o170000 != 0o040000 { return Err(invalid()); }
    let value = json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,
            "rootIdentity":identity,"cwd":native_path(cwd).ok_or_else(invalid)?}});
    check_value(&value).map_err(|_| invalid())?;
    let mut bytes = bounded(&value, REQUEST_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n'); Ok(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome { Complete, Refused, Cancelled, TimedOut, Failed, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable, IntentExpired,
    StaleIntent, SavedConfigMissing, SavedConfigInvalid, SavedConfigChanged, SavedConfigSensitive, SavedConfigUnsafe,
    SavedConfigTooLarge, PlatformDisabled, ProjectAdmissionRefused, InputLimit, ResultLimit, CommandIncomplete, CleanupUnknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CoreStatus { Pass, Fail, Missing, Blocked, Invalid, Skip, Manual, Configured, NotApplicable }
const CORE_STATUSES: [CoreStatus; 9] = [CoreStatus::Pass, CoreStatus::Fail, CoreStatus::Missing, CoreStatus::Blocked,
    CoreStatus::Invalid, CoreStatus::Skip, CoreStatus::Manual, CoreStatus::Configured, CoreStatus::NotApplicable];
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CheckId { VersionSource, PlatformSelection, AndroidModule, AndroidGradleWrapper, AndroidDebugIdentity,
    WorkspacePrivateOutput, AndroidArtifact, PreflightEarlyExit, ConfigurationPolicy, MetadataPolicy,
    ConfiguredProjectCheck, CoreLifecycle, OtherCoreFinding }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Finding { ordinal: u32, check: CheckId, status: CoreStatus, message: CheckId, project_check_index: Option<u32> }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Limitation { SavedInputsNotAtomic, ProjectCodeEffectsPossible, NotNetworkIsolated, CoreBuildsDisabled,
    ArtifactValidationNotRequested, ToolkitSigningCredentialsStoreNotRequested, ReleaseReadinessNotAssessed }
const LIMITATIONS: [Limitation; 7] = [Limitation::SavedInputsNotAtomic, Limitation::ProjectCodeEffectsPossible,
    Limitation::NotNetworkIsolated, Limitation::CoreBuildsDisabled, Limitation::ArtifactValidationNotRequested,
    Limitation::ToolkitSigningCredentialsStoreNotRequested, Limitation::ReleaseReadinessNotAssessed];
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Summary { total: u32, shown: u32, omitted: u32, counts: BTreeMap<CoreStatus, u32> }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultData {
    schema_version: u32, scope: String, used_config: Content, findings: Vec<Finding>, summary: Summary, limitations: Vec<Limitation>,
}
impl ResultData {
    fn valid(&self, used: &Content) -> bool {
        let s = &self.summary;
        if self.schema_version != 1 || self.scope != "saved-offline-android-no-core-build" || &self.used_config != used
            || !self.used_config.valid() || self.limitations.as_slice() != LIMITATIONS || s.total > 4096
            || s.shown != s.total.min(128) || s.omitted != s.total - s.shown || self.findings.len() != s.shown as usize
            || s.counts.len() != CORE_STATUSES.len() || !CORE_STATUSES.iter().all(|key| s.counts.get(key).is_some_and(|n| *n <= 4096))
            || s.counts.values().copied().sum::<u32>() != s.total { return false; }
        let mut shown = BTreeMap::<CoreStatus, u32>::new();
        for (index, finding) in self.findings.iter().enumerate() {
            if finding.ordinal as usize != index || finding.message != finding.check
                || finding.project_check_index.is_some_and(|n| finding.check != CheckId::ConfiguredProjectCheck || n > 31) { return false; }
            *shown.entry(finding.status).or_default() += 1;
        }
        shown.iter().all(|(key, count)| s.counts.get(key).is_some_and(|total| count <= total))
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CoreStop { None, Cancelled, TimedOut }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Lifetime {
    complete: bool, fatal: bool, contained: bool, command_dispatched: Option<bool>, commands: u32, profile_calls: u32,
    input_closed: bool, handlers_restored: bool, invocation_closed: bool, stop_observed: CoreStop,
}
impl Lifetime {
    pub(crate) fn settled(&self) -> bool { self.complete && !self.fatal && self.contained && self.command_dispatched.is_some()
        && self.input_closed && self.handlers_restored && self.invocation_closed && self.profile_calls == 0 }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Terminal {
    schema_version: u32, context: Context, pub(crate) outcome: Outcome, pub(crate) reason: Reason,
    pub(crate) result: Option<ResultData>, pub(crate) lifetime: Lifetime,
}
impl Terminal {
    fn valid(&self, context: &Context) -> bool {
        if self.schema_version != 1 || &self.context != context || !self.context.valid() || self.lifetime.profile_calls != 0
            || self.lifetime.commands > 4096 { return false; }
        if self.outcome == Outcome::Complete {
            return self.reason == Reason::None && self.lifetime.settled() && self.lifetime.stop_observed == CoreStop::None
                && self.result.as_ref().is_some_and(|r| r.valid(&context.saved_config));
        }
        if self.result.is_some() || self.reason == Reason::None { return false; }
        if self.outcome == Outcome::Unknown { return self.reason == Reason::CleanupUnknown && !self.lifetime.settled(); }
        if !self.lifetime.settled() { return false; }
        match self.outcome {
            Outcome::Cancelled => self.reason == Reason::Cancelled && self.lifetime.stop_observed == CoreStop::Cancelled,
            Outcome::TimedOut => self.reason == Reason::TimedOut && self.lifetime.stop_observed == CoreStop::TimedOut,
            Outcome::Refused | Outcome::Failed => true,
            _ => false,
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
pub(crate) fn decode(bytes: &[u8], operation: &str, generation: &str, context: &Context) -> Result<Frame, BridgeError> {
    if bytes.len() < 3 || bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") || bytes[0] != b'{'
        || bytes[bytes.len() - 2] != b'}' || bytes[..bytes.len() - 1].iter().any(|b| *b == b'\r' || *b == b'\n') { return Err(BridgeError::protocol()); }
    let value = strict_json(&bytes[..bytes.len() - 1])?;
    let envelope = Envelope::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    if envelope.protocol != PROTOCOL || envelope.operation_id != operation || envelope.owner_generation != generation
        || !token(operation) || !token(generation) { return Err(BridgeError::protocol()); }
    match (envelope.sequence, envelope.kind.as_str()) {
        (0, "accepted") => {
            let accepted = Accepted::deserialize(&envelope.payload).map_err(|_| BridgeError::protocol())?;
            if accepted.schema_version != 1 || &accepted.context != context || !accepted.context.valid() { return Err(BridgeError::protocol()); }
            Ok(Frame::Accepted)
        }
        (1, "terminal") => {
            // Required nullable fields cannot use serde's omitted-Option default.
            if !keys(&envelope.payload, &["schemaVersion", "context", "outcome", "reason", "result", "lifetime"])
                || !envelope.payload.get("lifetime").is_some_and(|l| keys(l, &["complete", "fatal", "contained", "commandDispatched", "commands",
                    "profileCalls", "inputClosed", "handlersRestored", "invocationClosed", "stopObserved"])) { return Err(BridgeError::protocol()); }
            if let Some(result) = envelope.payload.get("result").filter(|v| !v.is_null()) {
                let rows = result.get("findings").and_then(Value::as_array).ok_or_else(BridgeError::protocol)?;
                if rows.len() > 128 || rows.iter().any(|row| !keys(row, &["ordinal", "check", "status", "message", "projectCheckIndex"])) { return Err(BridgeError::protocol()); }
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
    pub(crate) intent_usable: bool, pub(crate) outcome: Option<Outcome>, pub(crate) reason: Reason, pub(crate) result: Option<ResultData>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32, pub(crate) status_revision: u32, pub(crate) availability: Availability, pub(crate) operation: Option<Projection>,
}

#[cfg(test)]
#[path = "offline_preflight_protocol_tests.rs"]
pub(crate) mod tests;
