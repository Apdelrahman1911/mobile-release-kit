//! Closed workflow DATA and private wire. No paths/templates supplied by a
//! renderer become authority, and no configuration frame is admitted here.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use crate::{edit_protocol::{self as edit, bounded, token, Capability, ChildFrame, CoreEditOutcome,
    CoreReason, Effect, Journal, NativeEditReason, NativeFinality, Phase, ResourceState},
    error::BridgeError, protocol::{check_value, strict_json}};

pub const PROTOCOL: &str = "mrk-github-workflows/1";
pub const DOMAIN: &str = "github_workflows";
pub const RESPONSE_LIMIT: usize = 256 * 1024;
pub const STATUS_LIMIT: usize = 1024 * 1024;
const OBSERVED_LIMIT: u32 = 1024 * 1024;
const GENERATED_LIMIT: u32 = 16 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowId { Preflight, Candidate, ExternalTesting, ProductionSubmit }
const IDS: [WorkflowId; 4] = [WorkflowId::Preflight, WorkflowId::Candidate, WorkflowId::ExternalTesting, WorkflowId::ProductionSubmit];
impl WorkflowId {
    pub(crate) fn path(self) -> &'static str {
        match self {
            Self::Preflight => ".github/workflows/mobile-preflight.yml",
            Self::Candidate => ".github/workflows/mobile-candidate.yml",
            Self::ExternalTesting => ".github/workflows/mobile-external-testing.yml",
            Self::ProductionSubmit => ".github/workflows/mobile-production-submit.yml",
        }
    }
}

fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|v| v.len() == names.len() && names.iter().all(|n| v.contains_key(*n)))
}
fn hex(value: &str, size: usize) -> bool {
    value.len() == size && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn plain(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
}
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn coordinate(value: &str) -> bool {
    let Some((owner, repository)) = value.split_once('/') else { return false; };
    let part = |text: &str, limit: usize, punctuation: &[u8]| !text.is_empty() && text.len() <= limit
        && text.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && text.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || punctuation.contains(&byte));
    part(owner, 39, b"-") && part(repository, 100, b"._-")
}
fn version(value: &str) -> bool {
    let pieces: Vec<&str> = value.split('.').collect();
    value.len() <= 32 && pieces.len() == 3 && pieces.iter().all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

pub(crate) fn value_bounds(value: &Value, depth_limit: usize, byte_limit: usize) -> Result<(), BridgeError> {
    check_value(value)?;
    let mut pending = vec![(value, 0usize)];
    let mut nodes = 0usize;
    while let Some((item, depth)) = pending.pop() {
        nodes += 1;
        if nodes > 8_000 || depth > depth_limit { return Err(BridgeError::invalid()); }
        match item {
            Value::Object(values) => {
                if depth >= depth_limit || nodes + pending.len() + 2 * values.len() > 8_000 { return Err(BridgeError::invalid()); }
                nodes += values.len(); // Count object keys, like the core.
                pending.extend(values.values().map(|v| (v, depth + 1)));
            }
            Value::Array(values) => {
                if depth >= depth_limit || nodes + pending.len() + values.len() > 8_000 { return Err(BridgeError::invalid()); }
                pending.extend(values.iter().map(|v| (v, depth + 1)));
            }
            _ => {},
        }
    }
    bounded(value, byte_limit).map(|_| ())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisteredIdentity {
    pub(crate) device: String, pub(crate) inode: String,
    pub(crate) mode: u32, pub(crate) uid: u32, pub(crate) gid: u32,
}
impl RegisteredIdentity {
    pub(crate) fn valid(&self) -> bool {
        [&self.device, &self.inode].into_iter().all(|s| !s.is_empty() && s.len() <= 20
            && s.bytes().all(|b| b.is_ascii_digit()) && (s.len() == 1 || !s.starts_with('0'))
            && s.parse::<u64>().is_ok())
            && self.inode != "0" && self.mode & 0o170000 == 0o040000
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum Observation {
    // A tagged unit variant ignores extra fields; this empty struct stays closed.
    Absent {},
    Present { #[serde(rename = "byteLength")] byte_length: u32, sha256: String },
}
impl Observation {
    fn valid(&self) -> bool {
        match self { Self::Absent {} => true, Self::Present { byte_length, sha256 } => *byte_length <= OBSERVED_LIMIT && hex(sha256, 64) }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum ObservedFile {
    Absent { id: WorkflowId },
    Present { id: WorkflowId, #[serde(rename = "byteLength")] byte_length: u32, sha256: String },
}
impl ObservedFile {
    fn id(&self) -> WorkflowId { match self { Self::Absent { id } | Self::Present { id, .. } => *id } }
    fn observation(&self) -> Observation {
        match self { Self::Absent { .. } => Observation::Absent {},
            Self::Present { byte_length, sha256, .. } => Observation::Present { byte_length: *byte_length, sha256: sha256.clone() } }
    }
}
fn observations_valid(observed: &[ObservedFile]) -> bool {
    observed.len() == 4 && observed.iter().zip(IDS).all(|(row, id)| row.id() == id && row.observation().valid())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action { Create, Preserve, Update }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Generated { pub content: String, pub byte_length: u32, pub sha256: String }
impl Generated {
    fn valid(&self) -> bool {
        self.byte_length > 0 && self.byte_length <= GENERATED_LIMIT
            && self.content.len() == self.byte_length as usize && hex(&self.sha256, 64)
            && digest(self.content.as_bytes()) == self.sha256
    }
}
fn present_previous<'de, D: serde::Deserializer<'de>>(value: D) -> Result<Option<Generated>, D::Error> {
    Generated::deserialize(value).map(Some) // An explicitly supplied null is not omission.
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileView {
    pub id: WorkflowId, pub path: String, pub action: Action, pub observed: Observation, pub generated: Generated,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_previous")]
    pub previous: Option<Generated>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateSet { pub core_version: String, pub resource_version: u32, pub resource_sha256: String }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tooling { pub repository: String, pub sha: String, pub schema_reference: String, pub state: String }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedView {
    pub schema_version: u32, pub files: Vec<FileView>, pub create_directories: Vec<String>,
    pub template_set: TemplateSet, pub tooling: Tooling,
}
pub(crate) fn tooling_coordinate_valid(repository: &str, sha: &str) -> bool {
    plain(repository, 140) && coordinate(repository) && hex(sha, 40)
}
pub(crate) fn template_tooling_valid(template: &TemplateSet, tooling: &Tooling) -> bool {
    version(&template.core_version) && template.resource_version == 1 && hex(&template.resource_sha256, 64)
        && tooling_coordinate_valid(&tooling.repository, &tooling.sha)
        && tooling.schema_reference == format!("https://raw.githubusercontent.com/{}/{}/schemas/project.schema.json", tooling.repository, tooling.sha)
        && tooling.state == "format-only"
}
impl PreparedView {
    fn valid(&self) -> bool {
        if self.schema_version != 1 || self.files.len() != 4 || bounded(self, RESPONSE_LIMIT).is_err()
            || !template_tooling_valid(&self.template_set, &self.tooling) { return false; }
        let mut generated_total = 0u32;
        let mut previous_total = 0u32;
        for (row, id) in self.files.iter().zip(IDS) {
            let generated = &row.generated;
            if row.id != id || row.path != id.path() || !row.observed.valid() || !generated.valid() { return false; }
            generated_total += generated.byte_length;
            match (&row.action, &row.observed, &row.previous) {
                (Action::Create, Observation::Absent {}, None) => {},
                (Action::Preserve, Observation::Present { byte_length, sha256 }, None)
                    if *byte_length == generated.byte_length && *sha256 == generated.sha256 => {},
                (Action::Update, Observation::Present { byte_length, sha256 }, Some(previous))
                    if previous.valid() && *byte_length == previous.byte_length && *sha256 == previous.sha256
                        && previous.content != generated.content && previous.sha256 != generated.sha256 => {
                            previous_total += previous.byte_length;
                        },
                _ => return false,
            }
        }
        let directories: Vec<&str> = self.create_directories.iter().map(String::as_str).collect();
        generated_total <= 64 * 1024 && previous_total <= 64 * 1024
            && matches!(directories.as_slice(), [] | [".github/workflows"] | [".github", ".github/workflows"])
            && (directories.is_empty() || self.files.iter().all(|f| f.action == Action::Create))
    }
    pub(crate) fn matches_observed(&self, observed: &[ObservedFile]) -> bool {
        observations_valid(observed) && self.files.len() == 4
            && self.files.iter().zip(observed).all(|(file, old)| file.id == old.id() && file.observed == old.observation())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictFile { pub id: WorkflowId, pub observed: Observation }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConflictView { pub schema_version: u32, pub reason: String, pub conflicts: Vec<ConflictFile> }
impl ConflictView {
    fn valid(&self) -> bool {
        if self.schema_version != 1 || self.reason != "existing_workflow_differs"
            || self.conflicts.is_empty() || self.conflicts.len() > 4 || bounded(self, 4096).is_err() { return false; }
        let mut previous = None;
        self.conflicts.iter().all(|row| {
            let index = IDS.iter().position(|id| *id == row.id).unwrap_or(4);
            let ordered = previous.is_none_or(|old| index > old); previous = Some(index);
            ordered && index < 4 && matches!(row.observed, Observation::Present { .. }) && row.observed.valid()
        })
    }
    pub(crate) fn matches_observed(&self, observed: &[ObservedFile]) -> bool {
        observations_valid(observed) && self.conflicts.iter().all(|file|
            observed.iter().any(|old| old.id() == file.id && file.observed == old.observation()))
    }
}


#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction { Rollback, CommittedCleanup, RolledBackCleanup, PreparingCleanup }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState { Idle, Conflict, Recoverable }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryFileAction { Preserve, Remove, Restore }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoverySummary { pub size: u32, pub mode: u32, pub sha256: String }
impl RecoverySummary {
    fn valid(&self, staged: bool) -> bool {
        self.size <= if staged { GENERATED_LIMIT } else { OBSERVED_LIMIT }
            && (!staged || self.size > 0) && self.mode <= 0o7777 && hex(&self.sha256, 64)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryFile {
    pub id: WorkflowId, pub path: String, pub action: RecoveryFileAction,
    pub before: Option<RecoverySummary>, pub after: Option<RecoverySummary>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryCleanup { pub file_count: u32, pub directory_count: u32, pub scope: String }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryView {
    pub schema_version: u32, pub kind: String, pub state: RecoveryState,
    pub action: Option<RecoveryAction>, pub transaction_id: Option<String>,
    pub files: Vec<RecoveryFile>, pub private_cleanup: RecoveryCleanup,
}
impl RecoveryView {
    pub(crate) fn valid(&self) -> bool {
        if self.schema_version != 1 || self.kind != "recovery" || bounded(self, 4096).is_err()
            || self.private_cleanup.scope != "inspected-workflow-journal-only"
            || self.private_cleanup.file_count > 16 || self.private_cleanup.directory_count > 2
            || self.private_cleanup.file_count + self.private_cleanup.directory_count > 16 { return false; }
        if self.state != RecoveryState::Recoverable {
            return self.action.is_none() && self.transaction_id.is_none() && self.files.is_empty()
                && self.private_cleanup.file_count == 0 && self.private_cleanup.directory_count == 0;
        }
        if self.action.is_none() || !self.transaction_id.as_deref().is_some_and(token)
            || self.files.len() != 4 || self.private_cleanup.file_count < 2 { return false; }
        self.files.iter().zip(IDS).all(|(file, id)| {
            let action = if self.action != Some(RecoveryAction::Rollback) || file.after.is_none() { RecoveryFileAction::Preserve }
                else if file.before.is_none() { RecoveryFileAction::Remove } else { RecoveryFileAction::Restore };
            file.id == id && file.path == id.path() && file.action == action
                && file.before.as_ref().is_none_or(|s| s.valid(false))
                && file.after.as_ref().is_none_or(|s| s.valid(true))
                && (file.before.is_some() || file.after.is_some())
                && match (&file.before, &file.after) { (Some(before), Some(after)) => before.mode == after.mode, _ => true }
        })
    }
    pub(crate) fn expected_success(&self) -> Option<(Effect, Journal)> {
        if !self.valid() || self.state != RecoveryState::Recoverable { return None; }
        let effect = match self.action? {
            RecoveryAction::CommittedCleanup => Effect::Committed,
            RecoveryAction::Rollback | RecoveryAction::RolledBackCleanup => Effect::RolledBack,
            RecoveryAction::PreparingCleanup => Effect::NotStarted,
        };
        Some((effect, Journal::Clean))
    }
}
fn recovery_shape(value: &Value) -> bool {
    keys(value, &["schemaVersion", "kind", "state", "action", "transactionId", "files", "privateCleanup"])
        && keys(&value["privateCleanup"], &["fileCount", "directoryCount", "scope"])
        && value["files"].as_array().is_some_and(|files| files.iter().all(|file|
            keys(file, &["id", "path", "action", "before", "after"])
                && ["before", "after"].into_iter().all(|key| file[key].is_null()
                    || keys(&file[key], &["size", "mode", "sha256"]))))
}
#[derive(Clone, Serialize)]
pub struct RecoveryCheckout { pub revision: String, pub view: RecoveryView }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryPrepared { pub revision: String, pub plan_token: String, pub view: RecoveryView }
#[derive(Clone, Default, Serialize)]
pub struct RecoveryDetails { pub checkout: Option<RecoveryCheckout>, pub prepared: Option<RecoveryPrepared> }
impl RecoveryDetails {
    pub(crate) fn terminal_admissible(&self, applied: bool, core: &CoreEditOutcome) -> bool {
        if core.effect == Effect::Unchanged || applied && self.prepared.is_none()
            || !applied && core.journal == Journal::Clean { return false; }
        let view = self.checkout.as_ref().map(|c| &c.view);
        if let Some(view) = view {
            let effect_valid = match view.action {
                Some(RecoveryAction::CommittedCleanup) => core.effect == Effect::Committed,
                Some(RecoveryAction::RolledBackCleanup) => core.effect == Effect::RolledBack,
                Some(RecoveryAction::PreparingCleanup) => core.effect == Effect::NotStarted,
                Some(RecoveryAction::Rollback) => core.effect == Effect::NotStarted
                    || applied && matches!(core.effect, Effect::RolledBack | Effect::Unknown),
                None => core.effect == Effect::NotStarted,
            };
            if !effect_valid || view.state == RecoveryState::Recoverable && core.journal == Journal::NotCreated { return false; }
        }
        if applied && core.reason == CoreReason::None {
            return self.prepared.as_ref().and_then(|p| p.view.expected_success())
                .is_some_and(|(effect, journal)| core.effect == effect && core.journal == journal && core.resources == ResourceState::Settled);
        }
        true
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryOpened { pub revision: String, pub recovery: RecoveryView, pub scope_resources: ResourceState }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryPreparedReply { pub revision: String, pub plan_token: String, pub recovery: RecoveryView, pub scope_resources: ResourceState }
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecoveryIntent { Recover }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareWorkflowRecovery { pub session_id: String, pub revision: String, pub intent: RecoveryIntent }

#[derive(Clone, Serialize)]
pub struct Checkout { pub revision: String, pub observed: Vec<ObservedFile> }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Prepared { pub revision: String, pub plan_token: String, pub draft_revision: u32, pub baseline_generation: u32, pub view: PreparedView }
#[derive(Clone, Default)]
pub(crate) struct Details {
    pub(crate) checkout: Option<Checkout>, pub(crate) prepared: Option<Prepared>, pub(crate) conflict: Option<ConflictView>,
    pub(crate) recovery: Option<RecoveryDetails>,
}
impl Details {
    pub(crate) fn recovery() -> Self { Self { recovery: Some(RecoveryDetails::default()), ..Self::default() } }
    pub(crate) fn revision(&self) -> Option<&str> {
        if let Some(recovery) = &self.recovery { recovery.checkout.as_ref().map(|c| c.revision.as_str()) }
        else { self.checkout.as_ref().map(|c| c.revision.as_str()) }
    }
    pub(crate) fn plan_token(&self) -> Option<&str> {
        if let Some(recovery) = &self.recovery { recovery.prepared.as_ref().map(|p| p.plan_token.as_str()) }
        else { self.prepared.as_ref().map(|p| p.plan_token.as_str()) }
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Projection {
    pub domain: &'static str, pub project_id: String, pub session_id: String, pub owner_generation: String,
    pub phase: Phase, pub review_remaining_ms: u32, pub checkout: Option<Checkout>, pub prepared: Option<Prepared>,
    pub conflict: Option<ConflictView>, pub apply_submitted: bool, pub core_outcome: Option<CoreEditOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryDetails>,
    pub native_reason: NativeEditReason, pub native_finality: NativeFinality, pub late_settled: bool,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowEditStatus {
    pub schema_version: u32, pub domain: &'static str, pub window_generation: String, pub status_revision: u32,
    pub capability: Capability, pub active: Option<Projection>, pub last_terminal: Option<Projection>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareWorkflowEdit {
    pub session_id: String, pub revision: String, pub draft: Value,
    pub tooling_repository: String, pub tooling_sha: String,
    pub draft_revision: u32, pub baseline_generation: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Opened { pub revision: String, pub observed: Vec<ObservedFile>, pub scope_resources: ResourceState }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedReply { pub revision: String, pub plan_token: String, pub view: PreparedView, pub scope_resources: ResourceState }
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum TerminalReply {
    Outcome { #[serde(rename = "planToken")] plan_token: Option<String>, effect: Effect, journal: Journal, resources: ResourceState, reason: CoreReason },
    Conflict { revision: String, effect: Effect, journal: Journal, resources: ResourceState, reason: CoreReason, conflict: ConflictView },
}
impl TerminalReply {
    pub(crate) fn outcome(&self) -> CoreEditOutcome {
        let (effect, journal, resources, reason) = match self {
            Self::Outcome { effect, journal, resources, reason, .. } | Self::Conflict { effect, journal, resources, reason, .. } => (effect, journal, resources, reason),
        };
        CoreEditOutcome { effect: effect.clone(), journal: journal.clone(), resources: resources.clone(), reason: reason.clone() }
    }
    pub(crate) fn plan_token(&self) -> Option<&str> { match self { Self::Outcome { plan_token, .. } => plan_token.as_deref(), Self::Conflict { .. } => None } }
}

pub(crate) fn request(session: &str, seq: u32, op: &str, params: Value) -> Result<Vec<u8>, BridgeError> {
    if !token(session) || seq > 2 { return Err(BridgeError::invalid()); }
    let legal = match (seq, op) {
        (0, "open") => (keys(&params, &["root", "registeredIdentity"])
            || keys(&params, &["root", "registeredIdentity", "intent"]) && params["intent"] == "recover")
            && params["root"].as_str().is_some_and(|s| s.len() <= 4096)
            && serde_json::from_value::<RegisteredIdentity>(params["registeredIdentity"].clone()).is_ok_and(|id| id.valid()),
        (1, "prepare") if params.get("intent").is_some() => keys(&params, &["revision", "intent"])
            && params["intent"] == "recover" && params["revision"].as_str().is_some_and(token),
        (1, "prepare") => keys(&params, &["revision", "draft", "toolingRepository", "toolingSha"])
            && params["revision"].as_str().is_some_and(token) && params["draft"].is_object()
            && params["toolingRepository"].as_str().is_some_and(|s| s.len() <= 140)
            && params["toolingSha"].as_str().is_some_and(|s| s.len() <= 40)
            && value_bounds(&params["draft"], 28, 512 * 1024).is_ok(),
        (2, "apply") => (keys(&params, &["planToken"])
            || keys(&params, &["planToken", "intent"]) && params["intent"] == "recover")
            && params["planToken"].as_str().is_some_and(token),
        (1 | 2, "discard") => keys(&params, &[]),
        _ => false,
    };
    if !legal { return Err(BridgeError::invalid()); }
    let value = json!({"protocol": PROTOCOL, "session": session, "seq": seq, "op": op, "params": params});
    check_value(&value)?;
    let mut bytes = bounded(&value, edit::REQUEST_LIMIT - 1)?; bytes.push(b'\n'); Ok(bytes)
}

pub(crate) fn decode(bytes: &[u8], session: &str) -> Result<ChildFrame, BridgeError> {
    if bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &bytes[..bytes.len() - 1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}') || body.iter().any(|b| matches!(*b, b'\r' | b'\n')) { return Err(BridgeError::protocol()); }
    let value = strict_json(body)?;
    if !keys(&value, &["protocol", "session", "seq", "kind", "result"]) || value["protocol"] != PROTOCOL || value["session"] != session { return Err(BridgeError::protocol()); }
    let seq = value["seq"].as_u64().filter(|n| *n <= 2).ok_or_else(BridgeError::protocol)? as u32;
    let raw = &value["result"];
    value_bounds(raw, 16, RESPONSE_LIMIT).map_err(|_| BridgeError::protocol())?;
    match value["kind"].as_str() {
        Some("opened") if seq == 0 && raw.get("recovery").is_some() => {
            if !keys(raw, &["revision", "recovery", "scopeResources"]) || !recovery_shape(&raw["recovery"]) { return Err(BridgeError::protocol()); }
            let result: RecoveryOpened = serde_json::from_value(raw.clone()).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || result.scope_resources != ResourceState::Settled || !result.recovery.valid() { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::WorkflowRecoveryOpened(result))
        }
        Some("opened") if seq == 0 => {
            if !keys(raw, &["revision", "observed", "scopeResources"]) { return Err(BridgeError::protocol()); }
            let result: Opened = serde_json::from_value(raw.clone()).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || result.scope_resources != ResourceState::Settled || !observations_valid(&result.observed) { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::WorkflowOpened(result))
        }
        Some("prepared") if seq == 1 && raw.get("recovery").is_some() => {
            if !keys(raw, &["revision", "planToken", "recovery", "scopeResources"]) || !recovery_shape(&raw["recovery"]) { return Err(BridgeError::protocol()); }
            let result: RecoveryPreparedReply = serde_json::from_value(raw.clone()).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !token(&result.plan_token) || result.revision == result.plan_token
                || result.scope_resources != ResourceState::Settled || !result.recovery.valid()
                || result.recovery.state != RecoveryState::Recoverable { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::WorkflowRecoveryPrepared(result))
        }
        Some("prepared") if seq == 1 => {
            if !keys(raw, &["revision", "planToken", "view", "scopeResources"]) { return Err(BridgeError::protocol()); }
            let result: PreparedReply = serde_json::from_value(raw.clone()).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !token(&result.plan_token) || result.revision == result.plan_token
                || result.scope_resources != ResourceState::Settled || !result.view.valid() { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::WorkflowPrepared(result))
        }
        Some("terminal") if bytes.len() <= edit::TERMINAL_LIMIT => {
            let shape = match raw["kind"].as_str() {
                Some("outcome") => keys(raw, &["kind", "planToken", "effect", "journal", "resources", "reason"]),
                Some("conflict") if seq == 1 => keys(raw, &["kind", "revision", "effect", "journal", "resources", "reason", "conflict"]),
                _ => false,
            };
            if !shape { return Err(BridgeError::protocol()); }
            let result: TerminalReply = serde_json::from_value(raw.clone()).map_err(|_| BridgeError::protocol())?;
            let core = result.outcome();
            if !core.valid() || core.reason == CoreReason::IgnoreConflict || result.plan_token().is_some_and(|s| !token(s)) { return Err(BridgeError::protocol()); }
            if let TerminalReply::Conflict { revision, conflict, .. } = &result {
                if !token(revision) || !conflict.valid() || core.effect != Effect::NotStarted || core.journal != Journal::NotCreated { return Err(BridgeError::protocol()); }
            }
            Ok(ChildFrame::WorkflowTerminal(seq, result))
        }
        _ => Err(BridgeError::protocol()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SESSION: &str = "0123456789abcdef0123456789abcdef";
    const REVISION: &str = "fedcba9876543210fedcba9876543210";
    fn identity() -> Value { json!({"device":"0","inode":"18446744073709551615","mode":0o40755,"uid":1000,"gid":1001}) }
    fn frame(seq: u32, kind: &str, result: Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"session":SESSION,"seq":seq,"kind":kind,"result":result})).unwrap();
        bytes.push(b'\n'); bytes
    }
    fn view(preserve: bool) -> Value {
        let content = "name: inert\n";
        let files: Vec<Value> = IDS.into_iter().map(|id| json!({"id":id,"path":id.path(),
            "action":if preserve { "preserve" } else { "create" },
            "observed":if preserve { json!({"state":"present","byteLength":content.len(),"sha256":digest(content.as_bytes())}) } else { json!({"state":"absent"}) },
            "generated":{"content":content,"byteLength":content.len(),"sha256":digest(content.as_bytes())}})).collect();
        json!({"schemaVersion":1,"files":files,"createDirectories":[],
            "templateSet":{"coreVersion":"0.3.0","resourceVersion":1,"resourceSha256":"a".repeat(64)},
            "tooling":{"repository":"example/toolkit","sha":"0".repeat(40),
                "schemaReference":format!("https://raw.githubusercontent.com/example/toolkit/{}/schemas/project.schema.json","0".repeat(40)),"state":"format-only"}})
    }
    fn prepared(view: Value) -> Vec<u8> {
        frame(1,"prepared",json!({"revision":REVISION,"planToken":"b".repeat(32),"view":view,"scopeResources":"settled"}))
    }
    #[test]
    fn private_identity_is_full_strict_and_not_configuration_authority() {
        let open = json!({"root":"/inert/project","registeredIdentity":identity()});
        assert!(request(SESSION, 0, "open", open.clone()).is_ok());
        assert!(edit::request(SESSION, 0, "open", open.clone()).is_err());
        assert!(request(SESSION, 0, "open", json!({"root":"/inert/project"})).is_err());
        for (key, value) in [("device",json!(1)), ("device",json!("01")), ("device",json!("+1")),
            ("inode",json!("0")), ("inode",json!("18446744073709551616")), ("mode",json!(0o755)),
            ("uid",json!(true)), ("gid",json!(1.0)), ("gid",json!(4294967296u64))] {
            let mut bad = open.clone(); bad["registeredIdentity"][key] = value;
            assert!(request(SESSION, 0, "open", bad).is_err());
        }
        let mut extra = open; extra["registeredIdentity"]["owner"] = json!(1000);
        assert!(request(SESSION, 0, "open", extra).is_err());
    }
    #[test]
    fn conflict_is_bounded_terminal_data_without_a_token_or_generated_text() {
        let result = json!({"kind":"conflict","revision":REVISION,"effect":"not_started","journal":"not_created",
            "resources":"settled","reason":"none","conflict":{"schemaVersion":1,"reason":"existing_workflow_differs",
            "conflicts":[{"id":"candidate","observed":{"state":"present","byteLength":10,"sha256":"a".repeat(64)}}]}});
        assert!(matches!(decode(&frame(1,"terminal",result.clone()), SESSION), Ok(ChildFrame::WorkflowTerminal(1, _))));
        assert!(edit::decode(&frame(1,"terminal",result.clone()), SESSION).is_err());
        for (key, value) in [("planToken",json!(REVISION)), ("view",json!({})), ("reason",json!("ignore_conflict"))] {
            let mut bad = result.clone(); bad[key] = value; assert!(decode(&frame(1,"terminal",bad),SESSION).is_err());
        }
        assert!(decode(&frame(0,"terminal",result),SESSION).is_err());
    }
    #[test]
    fn prepare_has_no_snapshot_base_path_yaml_or_force_surface() {
        let params = json!({"revision":REVISION,"draft":{},"toolingRepository":"example/toolkit","toolingSha":"A".repeat(40)});
        assert!(request(SESSION,1,"prepare",params.clone()).is_ok()); // Pin policy remains core-owned.
        for key in ["suppliedSnapshot","expectedBase","root","files","content","sha256","force","token"] {
            let mut bad = params.clone(); bad[key] = Value::Null; assert!(request(SESSION,1,"prepare",bad).is_err());
        }
        let mut bad = params; bad["draft"] = json!({"large":"x".repeat(512*1024)});
        assert!(request(SESSION,1,"prepare",bad).is_err());
    }
    #[test]
    fn prepared_review_requires_exact_roster_paths_generated_bytes_and_observations() {
        for preserve in [false,true] {
            let original = view(preserve);
            assert!(matches!(decode(&prepared(original.clone()),SESSION), Ok(ChildFrame::WorkflowPrepared(_))), "literal valid baseline; preserve={preserve}");
            assert!(edit::decode(&prepared(original.clone()),SESSION).is_err(), "literal configuration-wire separation; preserve={preserve}");
            for (label, key, value) in [("file-id-candidate","id",json!("candidate")), ("file-path-other","path",json!(".github/workflows/other.yml")),
                ("file-action-replace","action",json!("replace")), ("observed-absent-extra-byteLength-zero","observed",json!({"state":"absent","byteLength":0}))] {
                let mut bad = original.clone(); bad["files"][0][key] = value;
                assert!(decode(&prepared(bad),SESSION).is_err(), "literal mutation {label}; preserve={preserve}");
            }
            for (label, key, value) in [("generated-content-different","content",json!("different\n")), ("generated-byteLength-zero","byteLength",json!(0)),
                ("generated-byteLength-float","byteLength",json!(12.0)), ("generated-byteLength-bool","byteLength",json!(true)), ("generated-sha256-different","sha256",json!("b".repeat(64)))] {
                let mut bad = original.clone(); bad["files"][0]["generated"][key] = value;
                assert!(decode(&prepared(bad),SESSION).is_err(), "literal mutation {label}; preserve={preserve}");
            }
            let mut bad = original.clone(); bad["files"].as_array_mut().unwrap().swap(0,1);
            assert!(decode(&prepared(bad),SESSION).is_err(), "literal mutation roster-reorder; preserve={preserve}");
            let mut bad = original; bad["files"].as_array_mut().unwrap().pop();
            assert!(decode(&prepared(bad),SESSION).is_err(), "literal mutation roster-drop; preserve={preserve}");
        }
        let mut bad = view(true); bad["files"][0]["observed"]["sha256"] = json!("b".repeat(64));
        assert!(decode(&prepared(bad),SESSION).is_err(), "literal mutation observed-sha256-different; preserve=true");
        let mut bad = view(false); bad["files"][0]["action"] = json!("preserve");
        assert!(decode(&prepared(bad),SESSION).is_err(), "literal mutation create-action-preserve; preserve=false");
    }
    #[test]
    fn observation_variants_reject_extra_fields_without_changing_json() {
        let absent = json!({"state":"absent"});
        let present = json!({"state":"present","byteLength":12,"sha256":"a".repeat(64)});
        for (label, original) in [("observation-absent",absent.clone()), ("observation-present",present.clone())] {
            let decoded: Observation = serde_json::from_value(original.clone()).unwrap();
            assert!(decoded.valid(), "literal valid shape {label}");
            assert!(serde_json::to_value(&decoded).unwrap() == original, "literal unchanged JSON shape {label}");
        }
        assert!(serde_json::to_string(&Observation::Absent {}).unwrap() == r#"{"state":"absent"}"#, "literal exact observation-absent JSON");
        for (label, key, value) in [("observation-absent-extra-byteLength-zero","byteLength",json!(0)),
            ("observation-absent-extra-sha256","sha256",json!("a".repeat(64))),
            ("observation-absent-extra-id","id",json!("preflight")), ("observation-absent-extra-unrelated","unrelated",json!(true))] {
            let mut bad = absent.clone(); bad[key] = value;
            assert!(serde_json::from_value::<Observation>(bad).is_err(), "literal mutation {label}");
        }
        let mut bad = present; bad["unrelated"] = json!(true);
        assert!(serde_json::from_value::<Observation>(bad).is_err(), "literal mutation observation-present-extra-unrelated");

        let absent = json!({"state":"absent","id":"preflight"});
        let present = json!({"state":"present","id":"preflight","byteLength":12,"sha256":"a".repeat(64)});
        for (label, original) in [("observed-file-absent",absent.clone()), ("observed-file-present",present.clone())] {
            let decoded: ObservedFile = serde_json::from_value(original.clone()).unwrap();
            assert!(decoded.id() == WorkflowId::Preflight && decoded.observation().valid(), "literal valid shape {label}");
            assert!(serde_json::to_value(&decoded).unwrap() == original, "literal unchanged JSON shape {label}");
        }
        for (label, key, value) in [("observed-file-absent-extra-byteLength-zero","byteLength",json!(0)),
            ("observed-file-absent-extra-unrelated","unrelated",json!(true))] {
            let mut bad = absent.clone(); bad[key] = value;
            assert!(serde_json::from_value::<ObservedFile>(bad).is_err(), "literal mutation {label}");
        }
        let mut bad = present; bad["unrelated"] = json!(true);
        assert!(serde_json::from_value::<ObservedFile>(bad).is_err(), "literal mutation observed-file-present-extra-unrelated");
    }
    #[test]
    fn canonical_update_view_requires_complete_matching_previous_content() {
        let mut updated = view(true);
        let content = "name: previous é\n";
        let previous = json!({"content":content,"byteLength":content.len(),"sha256":digest(content.as_bytes())});
        updated["files"][0]["action"] = json!("update");
        updated["files"][0]["previous"] = previous.clone();
        updated["files"][0]["observed"] = json!({"state":"present","byteLength":content.len(),"sha256":previous["sha256"]});
        assert!(decode(&prepared(updated.clone()),SESSION).is_ok());
        let decoded: PreparedView = serde_json::from_value(updated.clone()).unwrap();
        assert!(serde_json::to_value(decoded).unwrap() == updated);
        for case in ["missing", "null", "create", "preserve", "observation", "hash", "length", "extra", "same", "oversize"] {
            let mut bad = updated.clone();
            let file = &mut bad["files"][0];
            match case {
                "missing" => { file.as_object_mut().unwrap().remove("previous"); },
                "null" => file["previous"] = Value::Null,
                "create" | "preserve" => file["action"] = json!(case),
                "observation" => file["observed"]["sha256"] = json!("f".repeat(64)),
                "hash" => file["previous"]["sha256"] = json!("f".repeat(64)),
                "length" => file["previous"]["byteLength"] = json!(true),
                "extra" => file["previous"]["unrelated"] = json!(true),
                "same" => {
                    file["previous"] = file["generated"].clone();
                    file["observed"]["byteLength"] = file["generated"]["byteLength"].clone();
                    file["observed"]["sha256"] = file["generated"]["sha256"].clone();
                },
                "oversize" => file["previous"]["content"] = json!("x".repeat(16 * 1024 + 1)),
                _ => unreachable!(),
            }
            assert!(decode(&prepared(bad),SESSION).is_err(), "update mutation {case}");
        }
        for preserve in [false,true] {
            for previous in [Value::Null,previous.clone()] {
                let mut bad = view(preserve); bad["files"][0]["previous"] = previous;
                assert!(decode(&prepared(bad),SESSION).is_err(), "previous is update-only");
            }
        }
    }
    #[test]
    fn missing_directories_and_template_tooling_display_are_closed_data() {
        for directories in [json!([]),json!([".github/workflows"]),json!([".github",".github/workflows"])] {
            let mut candidate = view(false); candidate["createDirectories"] = directories;
            assert!(decode(&prepared(candidate),SESSION).is_ok());
        }
        for directories in [json!([".github"]),json!([".github/workflows",".github"]),json!([".github/workflows",".github/workflows"]),json!(["/tmp/elsewhere"])] {
            let mut bad = view(false); bad["createDirectories"] = directories;
            assert!(decode(&prepared(bad),SESSION).is_err());
        }
        let mut bad = view(true); bad["createDirectories"] = json!([".github/workflows"]);
        assert!(decode(&prepared(bad),SESSION).is_err());
        for (field, key, value) in [("templateSet","resourceVersion",json!(true)), ("templateSet","resourceVersion",json!(2)),
            ("templateSet","coreVersion",json!("0.3.0-custom")), ("templateSet","resourceSha256",json!("A".repeat(64))),
            ("tooling","repository",json!("example/toolkit/other")), ("tooling","sha",json!("A".repeat(40))),
            ("tooling","schemaReference",json!("https://example.invalid/schema")), ("tooling","state",json!("verified"))] {
            let mut bad = view(false); bad[field][key] = value;
            assert!(decode(&prepared(bad),SESSION).is_err());
        }
        let mut bad = view(false); bad["files"][0]["generated"]["content"] = json!("x".repeat(16*1024+1));
        assert!(decode(&prepared(bad),SESSION).is_err());
    }
    #[test]
    fn original_summary_must_match_prepared_and_conflict_receipts() {
        let prepared: PreparedView = serde_json::from_value(view(true)).unwrap();
        let summaries: Vec<ObservedFile> = prepared.files.iter().map(|file| ObservedFile::Present { id:file.id,
            byte_length:file.generated.byte_length,sha256:file.generated.sha256.clone() }).collect();
        assert!(prepared.matches_observed(&summaries));
        let mut changed = summaries.clone(); changed[0] = ObservedFile::Absent { id:WorkflowId::Preflight };
        assert!(!prepared.matches_observed(&changed));
        let conflict = ConflictView { schema_version:1,reason:"existing_workflow_differs".into(),
            conflicts:vec![ConflictFile { id:WorkflowId::Preflight,observed:summaries[0].observation() }] };
        assert!(conflict.valid()); assert!(conflict.matches_observed(&summaries));
        assert!(!conflict.matches_observed(&changed));
        let opened = json!({"revision":REVISION,"observed":summaries,"scopeResources":"settled"});
        assert!(matches!(decode(&frame(0,"opened",opened.clone()),SESSION),Ok(ChildFrame::WorkflowOpened(_))));
        for (key,value) in [("base",json!({})),("registeredIdentity",identity()),("scopeResources",json!("unknown"))] {
            let mut bad = opened.clone(); bad[key] = value; assert!(decode(&frame(0,"opened",bad),SESSION).is_err());
        }
        let mut bad = opened; bad["observed"][0]["byteLength"] = json!(OBSERVED_LIMIT+1);
        assert!(decode(&frame(0,"opened",bad),SESSION).is_err());
    }
    #[test]
    fn refusal_never_carries_prepared_content_or_exceeds_the_existing_terminal_bound() {
        let base = json!({"kind":"conflict","revision":REVISION,"effect":"not_started","journal":"not_created",
            "resources":"settled","reason":"none","conflict":{"schemaVersion":1,"reason":"existing_workflow_differs",
                "conflicts":[{"id":"preflight","observed":{"state":"present","byteLength":1,"sha256":"a".repeat(64)}}]}});
        for (key,value) in [("generated",json!({"content":"not allowed"})), ("planToken",Value::Null), ("path",json!(".github/workflows/mobile-preflight.yml"))] {
            let mut bad = base.clone(); bad["conflict"]["conflicts"][0][key] = value;
            assert!(decode(&frame(1,"terminal",bad),SESSION).is_err());
        }
        for bad_rows in [json!([]),json!([{"id":"unknown","observed":{"state":"absent"}}]),
            json!([{"id":"preflight","observed":{"state":"absent"}}]) ] {
            let mut bad = base.clone(); bad["conflict"]["conflicts"] = bad_rows;
            assert!(decode(&frame(1,"terminal",bad),SESSION).is_err());
        }
        let mut bad = base; let first = bad["conflict"]["conflicts"][0].clone();
        bad["conflict"]["conflicts"].as_array_mut().unwrap().push(first);
        assert!(decode(&frame(1,"terminal",bad),SESSION).is_err());
        assert_eq!(edit::TERMINAL_LIMIT,16*1024);
        let oversized = frame(1,"terminal",json!({"kind":"outcome","planToken":null,"effect":"not_started",
            "journal":"not_created","resources":"settled","reason":"x".repeat(edit::TERMINAL_LIMIT)}));
        assert!(decode(&oversized,SESSION).is_err());
    }

    fn recovery_view(action: &str) -> Value {
        let files: Vec<Value> = IDS.into_iter().map(|id| json!({"id":id,"path":id.path(),
            "action":if action == "rollback" { "remove" } else { "preserve" },
            "before":null,"after":{"size":1,"mode":0o644,"sha256":"a".repeat(64)}})).collect();
        json!({"schemaVersion":1,"kind":"recovery","state":"recoverable","action":action,
            "transactionId":"c".repeat(32),"files":files,
            "privateCleanup":{"fileCount":6,"directoryCount":1,"scope":"inspected-workflow-journal-only"}})
    }
    fn recovery_opened(view: Value) -> Vec<u8> {
        frame(0,"opened",json!({"revision":REVISION,"recovery":view,"scopeResources":"settled"}))
    }
    #[test]
    fn recovery_uses_distinct_frames_and_four_fixed_non_installation_success_actions() {
        // Pure wire DATA, not a claim about an original native owner/close.
        for (action,effect) in [("rollback",Effect::RolledBack),("committed_cleanup",Effect::Committed),
            ("rolled_back_cleanup",Effect::RolledBack),("preparing_cleanup",Effect::NotStarted)] {
            let view = recovery_view(action);
            assert!(matches!(decode(&recovery_opened(view.clone()),SESSION),Ok(ChildFrame::WorkflowRecoveryOpened(_))));
            let prepared = frame(1,"prepared",json!({"revision":REVISION,"planToken":"b".repeat(32),
                "recovery":view.clone(),"scopeResources":"settled"}));
            assert!(matches!(decode(&prepared,SESSION),Ok(ChildFrame::WorkflowRecoveryPrepared(_))));
            let typed: RecoveryView = serde_json::from_value(view).unwrap();
            assert_eq!(typed.expected_success(),Some((effect,Journal::Clean)));
            assert!(edit::decode(&prepared,SESSION).is_err());
        }
        for state in ["idle","conflict"] {
            let view = json!({"schemaVersion":1,"kind":"recovery","state":state,"action":null,
                "transactionId":null,"files":[],
                "privateCleanup":{"fileCount":0,"directoryCount":0,"scope":"inspected-workflow-journal-only"}});
            assert!(matches!(decode(&recovery_opened(view.clone()),SESSION),Ok(ChildFrame::WorkflowRecoveryOpened(_))));
            assert!(decode(&frame(1,"prepared",json!({"revision":REVISION,"planToken":"b".repeat(32),
                "recovery":view.clone(),"scopeResources":"settled"})),SESSION).is_err());
            for missing in ["action","transactionId"] {
                let mut bad = view.clone(); bad.as_object_mut().unwrap().remove(missing);
                assert!(decode(&recovery_opened(bad),SESSION).is_err());
            }
        }
    }
    #[test]
    fn recovery_view_requires_exact_roster_nullable_fields_and_bounded_summaries() {
        let view = recovery_view("rollback");
        for (key,value) in [("id",json!("candidate")),("path",json!("/private/user.yml")),
            ("action",json!("restore")),("content",json!("private contents")),("before",json!({}))] {
            let mut bad = view.clone(); bad["files"][0][key] = value;
            assert!(decode(&recovery_opened(bad),SESSION).is_err());
        }
        for (key,value) in [("size",json!(0)),("size",json!(GENERATED_LIMIT+1)),("size",json!(true)),
            ("mode",json!(0o100644)),("sha256",json!("A".repeat(64))),("content",json!("private contents"))] {
            let mut bad = view.clone(); bad["files"][0]["after"][key] = value;
            assert!(decode(&recovery_opened(bad),SESSION).is_err());
        }
        for key in ["before","after"] {
            let mut bad = view.clone(); bad["files"][0].as_object_mut().unwrap().remove(key);
            assert!(decode(&recovery_opened(bad),SESSION).is_err());
        }
        for value in [json!(17),json!(u32::MAX),json!(-1),json!(true)] {
            let mut bad = view.clone(); bad["privateCleanup"]["fileCount"] = value;
            assert!(decode(&recovery_opened(bad),SESSION).is_err());
        }
        let mut bad = view.clone(); bad["files"].as_array_mut().unwrap().reverse();
        assert!(decode(&recovery_opened(bad),SESSION).is_err());
        let mut bad = view.clone(); bad["files"].as_array_mut().unwrap().pop();
        assert!(decode(&recovery_opened(bad),SESSION).is_err());
        let mut bad = view; bad["files"][0]["before"] = json!({"size":1,"mode":0o600,"sha256":"b".repeat(64)});
        bad["files"][0]["action"] = json!("restore");
        assert!(decode(&recovery_opened(bad),SESSION).is_err()); // Before/after modes cannot disagree.
    }
    #[test]
    fn recovery_private_requests_never_accept_draft_pin_or_extra_file_authority() {
        for (seq,op,params) in [
            (0,"open",json!({"root":"/inert/project","registeredIdentity":identity(),"intent":"recover"})),
            (1,"prepare",json!({"revision":REVISION,"intent":"recover"})),
            (2,"apply",json!({"planToken":"b".repeat(32),"intent":"recover"})),
        ] {
            assert!(request(SESSION,seq,op,params.clone()).is_ok());
            assert!(edit::request(SESSION,seq,op,params.clone()).is_err());
            for intent in [json!("edit"),json!("rollback"),json!("Recover"),json!(true),Value::Null] {
                let mut bad = params.clone(); bad["intent"] = intent;
                assert!(request(SESSION,seq,op,bad).is_err());
            }
            for key in ["draft","toolingRepository","toolingSha","files","path","force","transactionId"] {
                let mut bad = params.clone(); bad[key] = Value::Null;
                assert!(request(SESSION,seq,op,bad).is_err());
            }
        }
    }
}
