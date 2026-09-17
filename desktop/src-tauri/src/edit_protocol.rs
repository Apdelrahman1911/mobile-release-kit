//! Data-only finite edit protocol. Tokens/status are not filesystem authority.
use std::io;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{error::BridgeError, protocol::{check_value, strict_json}};

pub const PROTOCOL: &str = "mrk-config-edit/1";
pub const REQUEST_LIMIT: usize = 1024 * 1024;
pub const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;
pub const TERMINAL_LIMIT: usize = 16 * 1024;
pub const STDOUT_LIMIT: usize = 12 * 1024 * 1024;
pub const STDERR_LIMIT: usize = 64 * 1024;
pub const STATUS_LIMIT: usize = 2 * 1024 * 1024;
const CONFIG_LIMIT: usize = 512 * 1024;
const IGNORE_LIMIT: u32 = 1024 * 1024;
const IGNORE_LINES: [&str; 4] = [".mobile-release/", ".mobile-release-init-prepare/", ".mobile-release-init/", ".mobile-release-init-cleanup/"];

pub fn token(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

struct Bounded { bytes: Vec<u8>, limit: usize }
impl io::Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bounded edit JSON"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
pub fn bounded<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, BridgeError> {
    let mut writer = Bounded { bytes: Vec::new(), limit };
    serde_json::to_writer(&mut writer, value).map_err(|_| BridgeError::invalid())?;
    Ok(writer.bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Effect { NotStarted, Unchanged, RolledBack, Committed, Unknown }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Journal { NotCreated, Clean, RecoveryRequired, Unknown }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState { Settled, Unknown }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoreReason { None, InvalidParams, InvalidConfig, IgnoreConflict, StaleRevision, PendingState, Busy, Cancelled, FilesystemError, CustodyUnknown, UnsupportedPlatform }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoreEditOutcome { pub effect: Effect, pub journal: Journal, pub resources: ResourceState, pub reason: CoreReason }
impl CoreEditOutcome {
    pub fn valid(&self) -> bool {
        !(self.effect == Effect::Unchanged && self.journal != Journal::NotCreated
            || matches!(self.effect, Effect::Committed | Effect::RolledBack) && self.journal == Journal::NotCreated
            || self.reason == CoreReason::None && (self.resources != ResourceState::Settled
                || self.effect == Effect::Unknown || matches!(self.journal, Journal::Unknown | Journal::RecoveryRequired)))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeEditReason { None, Discarded, Cancelled, ActiveTimeout, ReviewExpired, CallerLost, WindowLost, Shutdown, RuntimeUnavailable, SpawnFailed, ProtocolError, IoError, OutputLimit, CleanupUnknown }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase { Opening, Editing, Preparing, Reviewing, Applying, Finalizing, Final, Unknown }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeFinality { Pending, Settled, Unknown }
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EditAvailability { Available, UnsupportedPlatform, RuntimeUnqualified, CleanupUnknown, Shutdown, OtherEditActive }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EditDomain { Configuration, GitHubWorkflows }

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability { pub available: bool, pub reason: EditAvailability }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkout { pub revision: String, pub base: Value }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Prepared { pub revision: String, pub plan_token: String, pub draft_revision: u32, pub baseline_generation: u32, pub view: PreparedConfigView }
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditProjection {
    // Internal domain/custody are not configuration DTO fields. Workflow data
    // is projected only through its separately typed, domain-tagged surface.
    #[serde(skip)]
    pub(crate) domain: EditDomain,
    #[serde(skip)]
    pub(crate) workflow: Option<crate::github_workflow_edit_protocol::Details>,
    pub project_id: String, pub session_id: String, pub owner_generation: String,
    pub phase: Phase, pub review_remaining_ms: u32, pub checkout: Option<Checkout>,
    pub prepared: Option<Prepared>, pub apply_submitted: bool, pub core_outcome: Option<CoreEditOutcome>,
    pub native_reason: NativeEditReason, pub native_finality: NativeFinality, pub late_settled: bool,
}
impl EditProjection {
    pub(crate) fn revision(&self) -> Option<&str> {
        match self.domain {
            EditDomain::Configuration => self.checkout.as_ref().map(|c| c.revision.as_str()),
            EditDomain::GitHubWorkflows => self.workflow.as_ref()?.checkout.as_ref().map(|c| c.revision.as_str()),
        }
    }
    pub(crate) fn plan_token(&self) -> Option<&str> {
        match self.domain {
            EditDomain::Configuration => self.prepared.as_ref().map(|p| p.plan_token.as_str()),
            EditDomain::GitHubWorkflows => self.workflow.as_ref()?.prepared.as_ref().map(|p| p.plan_token.as_str()),
        }
    }
    pub(crate) fn workflow_projection(&self) -> Result<crate::github_workflow_edit_protocol::Projection, BridgeError> {
        use crate::github_workflow_edit_protocol::{DOMAIN, Projection};
        if self.domain != EditDomain::GitHubWorkflows { return Err(BridgeError::protocol()); }
        let detail = self.workflow.as_ref().ok_or_else(BridgeError::protocol)?;
        Ok(Projection { domain: DOMAIN, project_id: self.project_id.clone(), session_id: self.session_id.clone(),
            owner_generation: self.owner_generation.clone(), phase: self.phase, review_remaining_ms: self.review_remaining_ms,
            checkout: detail.checkout.clone(), prepared: detail.prepared.clone(), conflict: detail.conflict.clone(),
            apply_submitted: self.apply_submitted, core_outcome: self.core_outcome.clone(), native_reason: self.native_reason,
            native_finality: self.native_finality, late_settled: self.late_settled })
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigEditStatus {
    pub schema_version: u32, pub window_generation: String, pub status_revision: u32,
    pub capability: Capability, pub active: Option<EditProjection>, pub last_terminal: Option<EditProjection>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareConfigEdit {
    pub session_id: String, pub revision: String, pub expected_base: Value, pub draft: Value,
    pub draft_revision: u32, pub baseline_generation: u32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileView { pub path: String, pub action: String, pub before_bytes: Option<u32>, pub after_bytes: u32 }
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedConfigView {
    pub schema_version: u32, pub files: Vec<FileView>, pub create_release_directory: bool,
    pub rewrites_config_formatting: bool, pub ignore_additions: Vec<String>, pub preview: Value,
}

fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|v| v.len() == names.len() && names.iter().all(|name| v.contains_key(*name)))
}
fn text(value: &Value, limit: usize) -> bool {
    value.as_str().is_some_and(|s| s.len() <= limit && !s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}'))
}
fn assurance(value: &Value) -> bool {
    keys(value, &["basis", "projectCodeExecuted", "toolsProbed", "credentialsRead", "gitObserved", "storeContacted", "writesPerformed", "releaseReadiness"])
        && value["basis"] == "schema-policy" && value["releaseReadiness"] == "unknown"
        && ["projectCodeExecuted", "toolsProbed", "credentialsRead", "gitObserved", "storeContacted", "writesPerformed"].iter().all(|k| value[*k] == false)
}
fn summary(value: &Value) -> bool {
    if value["present"] == false { return keys(value, &["present"]); }
    if value["present"] != true { return false; }
    match value["type"].as_str() {
        Some("array" | "object") => keys(value, &["present", "type", "count"]) && value["count"].as_u64().is_some_and(|n| n <= u64::from(u32::MAX)),
        Some("null" | "boolean" | "number" | "string") => keys(value, &["present", "type"]),
        _ => false,
    }
}
fn preview(value: &Value) -> bool {
    if !keys(value, &["schemaVersion", "validation", "comparison", "fields", "assurance"])
        || value["schemaVersion"].as_u64() != Some(1) || !assurance(&value["assurance"]) { return false; }
    let validation = &value["validation"];
    if !keys(validation, &["valid", "state", "issues", "requirements", "assurance"])
        || validation["valid"] != true || validation["state"] != "format-valid"
        || !validation["issues"].as_array().is_some_and(Vec::is_empty) || !assurance(&validation["assurance"]) { return false; }
    let Some(requirements) = validation["requirements"].as_array() else { return false; };
    if requirements.len() > 64 || !requirements.iter().all(|v| {
        keys(v, &["name", "kind", "stage", "platform", "environment", "alternatives", "reason", "state"])
            && ["name", "kind", "stage", "platform", "environment", "reason"].iter().all(|k| text(&v[*k], 4096))
            && v["state"] == "unknown" && v["alternatives"].as_array().is_some_and(|a| a.len() <= 64 && a.iter().all(|s| text(s, 4096)))
    }) { return false; }
    let comparison = &value["comparison"];
    if !keys(comparison, &["baseProvided", "kind", "state", "semanticallyChanged", "counts", "changes", "unreviewedCount"])
        || !comparison["baseProvided"].is_boolean() || !comparison["semanticallyChanged"].is_boolean()
        || comparison["state"] != "complete" || comparison["unreviewedCount"].as_u64() != Some(0)
        || comparison["kind"] != if comparison["baseProvided"] == true { "compare" } else { "proposed-create" }
        || !keys(&comparison["counts"], &["added", "changed", "removed"]) { return false; }
    let Some(changes) = comparison["changes"].as_array() else { return false; };
    if changes.len() > 64 || !changes.iter().all(|v| keys(v, &["path", "operation", "before", "after"])
        && text(&v["path"], 256) && matches!(v["operation"].as_str(), Some("add" | "change" | "remove"))
        && summary(&v["before"]) && summary(&v["after"])) { return false; }
    for (operation, count) in [("add", "added"), ("change", "changed"), ("remove", "removed")] {
        if comparison["counts"][count].as_u64() != Some(changes.iter().filter(|v| v["operation"] == operation).count() as u64) { return false; }
    }
    value["fields"].as_array().is_some_and(|fields| fields.len() <= 64 && fields.iter().all(|v| {
        keys(v, &["path", "state", "present", "reason"]) && text(&v["path"], 256) && text(&v["reason"], 4096)
            && v["present"].is_boolean() && matches!(v["state"].as_str(), Some("required" | "optional" | "forbidden" | "unknown"))
    }))
}

impl PreparedConfigView {
    fn valid(&self) -> bool {
        if self.schema_version != 1 || self.files.len() != 2 || self.ignore_additions.len() > 4
            || bounded(self, 128 * 1024).is_err() || !preview(&self.preview) { return false; }
        for (file, path, limit, replacement) in [(&self.files[0], "release/mobile-release.json", CONFIG_LIMIT as u32, "replace"), (&self.files[1], ".gitignore", IGNORE_LIMIT, "append")] {
            if file.path != path || file.after_bytes > limit || file.before_bytes.is_some_and(|n| n > limit) { return false; }
            match file.action.as_str() {
                "create" if file.before_bytes.is_none() && file.after_bytes > 0 => {},
                "preserve" if file.before_bytes == Some(file.after_bytes) => {},
                action if action == replacement && file.before_bytes.is_some()
                    && (action != "append" || file.before_bytes.is_some_and(|n| file.after_bytes > n)) => {},
                _ => return false,
            }
        }
        let config = &self.files[0];
        let ignore = &self.files[1];
        let ordered: Vec<&str> = IGNORE_LINES.into_iter().filter(|line| self.ignore_additions.iter().any(|s| s == line)).collect();
        self.ignore_additions.iter().map(String::as_str).eq(ordered)
            && (ignore.action == "preserve") == self.ignore_additions.is_empty()
            && (ignore.action != "create" || self.ignore_additions.len() == 4)
            && self.rewrites_config_formatting == (config.action == "replace")
            && (!self.create_release_directory || config.action == "create")
            && self.preview["comparison"]["baseProvided"] == (config.action != "create")
            && self.preview["comparison"]["semanticallyChanged"] == (config.action != "preserve")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Opened { pub revision: String, pub base: Value, pub scope_resources: ResourceState }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedReply { pub revision: String, pub plan_token: String, pub view: PreparedConfigView, pub scope_resources: ResourceState }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalReply { pub plan_token: Option<String>, pub effect: Effect, pub journal: Journal, pub resources: ResourceState, pub reason: CoreReason }
impl TerminalReply {
    pub fn outcome(&self) -> CoreEditOutcome { CoreEditOutcome { effect: self.effect.clone(), journal: self.journal.clone(), resources: self.resources.clone(), reason: self.reason.clone() } }
}
pub enum ChildFrame {
    Opened(Opened), Prepared(PreparedReply), Terminal(u32, TerminalReply),
    WorkflowOpened(crate::github_workflow_edit_protocol::Opened),
    WorkflowPrepared(crate::github_workflow_edit_protocol::PreparedReply),
    WorkflowTerminal(u32, crate::github_workflow_edit_protocol::TerminalReply),
}
impl ChildFrame {
    pub(crate) fn domain(&self) -> EditDomain {
        match self {
            Self::Opened(_) | Self::Prepared(_) | Self::Terminal(..) => EditDomain::Configuration,
            Self::WorkflowOpened(_) | Self::WorkflowPrepared(_) | Self::WorkflowTerminal(..) => EditDomain::GitHubWorkflows,
        }
    }
}

pub fn request(session: &str, seq: u32, op: &str, params: Value) -> Result<Vec<u8>, BridgeError> {
    if !token(session) || seq > 2 { return Err(BridgeError::invalid()); }
    let legal = match (seq, op) {
        (0, "open") => keys(&params, &["root"]) && params["root"].as_str().is_some_and(|s| s.len() <= 4096),
        (1, "prepare") => keys(&params, &["revision", "expectedBase", "draft"])
            && params["revision"].as_str().is_some_and(token) && (params["expectedBase"].is_null() || params["expectedBase"].is_object())
            && params["draft"].is_object() && bounded(&params["expectedBase"], CONFIG_LIMIT).is_ok() && bounded(&params["draft"], CONFIG_LIMIT).is_ok(),
        (2, "apply") => keys(&params, &["planToken"]) && params["planToken"].as_str().is_some_and(token),
        (1 | 2, "discard") => keys(&params, &[]),
        _ => false,
    };
    if !legal { return Err(BridgeError::invalid()); }
    let value = json!({"protocol": PROTOCOL, "session": session, "seq": seq, "op": op, "params": params});
    check_value(&value)?;
    let mut bytes = bounded(&value, REQUEST_LIMIT - 1)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn decode(bytes: &[u8], session: &str) -> Result<ChildFrame, BridgeError> {
    if bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &bytes[..bytes.len() - 1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}') || body.iter().any(|b| *b == b'\r' || *b == b'\n') { return Err(BridgeError::protocol()); }
    let value = strict_json(body)?;
    if !keys(&value, &["protocol", "session", "seq", "kind", "result"]) || value["protocol"] != PROTOCOL || value["session"] != session {
        return Err(BridgeError::protocol());
    }
    let seq = value["seq"].as_u64().filter(|n| *n <= 2).ok_or_else(BridgeError::protocol)? as u32;
    match value["kind"].as_str() {
        Some("opened") if seq == 0 => {
            if !keys(&value["result"], &["revision", "base", "scopeResources"]) { return Err(BridgeError::protocol()); }
            let result: Opened = serde_json::from_value(value["result"].clone()).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !(result.base.is_null() || result.base.is_object())
                || bounded(&result.base, CONFIG_LIMIT).is_err() || result.scope_resources != ResourceState::Settled { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::Opened(result))
        }
        Some("prepared") if seq == 1 => {
            let raw = &value["result"];
            if !keys(raw, &["revision", "planToken", "view", "scopeResources"])
                || !keys(&raw["view"], &["schemaVersion", "files", "createReleaseDirectory", "rewritesConfigFormatting", "ignoreAdditions", "preview"])
                || !raw["view"]["files"].as_array().is_some_and(|files| files.len() == 2
                    && files.iter().all(|f| keys(f, &["path", "action", "beforeBytes", "afterBytes"]))) { return Err(BridgeError::protocol()); }
            let result: PreparedReply = serde_json::from_value(value["result"].clone()).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !token(&result.plan_token) || result.revision == result.plan_token
                || result.scope_resources != ResourceState::Settled || !result.view.valid() { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::Prepared(result))
        }
        Some("terminal") if bytes.len() <= TERMINAL_LIMIT => {
            if !keys(&value["result"], &["planToken", "effect", "journal", "resources", "reason"]) { return Err(BridgeError::protocol()); }
            let result: TerminalReply = serde_json::from_value(value["result"].clone()).map_err(|_| BridgeError::protocol())?;
            if result.plan_token.as_ref().is_some_and(|s| !token(s)) || !result.outcome().valid() { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::Terminal(seq, result))
        }
        _ => Err(BridgeError::protocol()),
    }
}
