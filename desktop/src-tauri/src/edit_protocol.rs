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
const IGNORE_LINES: [&str; 13] = [".mobile-release/", ".mobile-release-init-prepare/", ".mobile-release-init/", ".mobile-release-init-cleanup/",
    ".mobile-release-metadata-text-prepare/", ".mobile-release-metadata-text/", ".mobile-release-metadata-text-cleanup/",
    ".mobile-release-version-prepare/", ".mobile-release-version/", ".mobile-release-version-cleanup/",
    ".mobile-release-metadata-images-prepare/", ".mobile-release-metadata-images/", ".mobile-release-metadata-images-cleanup/"];

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EditDomain { Configuration, GitHubWorkflows, MetadataText, ReleaseVersion, MetadataImages }

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
    // Internal domain/custody are not configuration DTO fields. Other domains
    // are projected only through their separately typed, domain-tagged surfaces.
    #[serde(skip)]
    pub(crate) domain: EditDomain,
    #[serde(skip)]
    pub(crate) workflow: Option<crate::github_workflow_edit_protocol::Details>,
    #[serde(skip)]
    pub(crate) metadata_text: Option<crate::metadata_text_edit_protocol::Details>,
    #[serde(skip)]
    pub(crate) release_version: Option<crate::release_version_edit_protocol::Details>,
    #[serde(skip)]
    pub(crate) metadata_images: Option<crate::metadata_images_edit_protocol::Details>,
    pub project_id: String, pub session_id: String, pub owner_generation: String,
    pub phase: Phase, pub review_remaining_ms: u32, pub checkout: Option<Checkout>,
    pub prepared: Option<Prepared>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryDetails>,
    pub apply_submitted: bool, pub core_outcome: Option<CoreEditOutcome>,
    pub native_reason: NativeEditReason, pub native_finality: NativeFinality, pub late_settled: bool,
}
impl EditProjection {
    pub(crate) fn revision(&self) -> Option<&str> {
        match self.domain {
            EditDomain::Configuration => match &self.recovery {
                Some(recovery) => recovery.checkout.as_ref().map(|c| c.revision.as_str()),
                None => self.checkout.as_ref().map(|c| c.revision.as_str()),
            },
            EditDomain::GitHubWorkflows => self.workflow.as_ref()?.revision(),
            EditDomain::MetadataText => self.metadata_text.as_ref()?.revision(),
            EditDomain::ReleaseVersion => self.release_version.as_ref()?.revision(),
            EditDomain::MetadataImages => self.metadata_images.as_ref()?.checkout.as_ref().map(|c| c.revision.as_str()),
        }
    }
    pub(crate) fn plan_token(&self) -> Option<&str> {
        match self.domain {
            EditDomain::Configuration => match &self.recovery {
                Some(recovery) => recovery.prepared.as_ref().map(|p| p.plan_token.as_str()),
                None => self.prepared.as_ref().map(|p| p.plan_token.as_str()),
            },
            EditDomain::GitHubWorkflows => self.workflow.as_ref()?.plan_token(),
            EditDomain::MetadataText => self.metadata_text.as_ref()?.plan_token(),
            EditDomain::ReleaseVersion => self.release_version.as_ref()?.plan_token(),
            EditDomain::MetadataImages => self.metadata_images.as_ref()?.prepared.as_ref().map(|p| p.plan_token.as_str()),
        }
    }
    pub(crate) fn configuration_valid(&self) -> bool {
        self.domain == EditDomain::Configuration && self.workflow.is_none() && self.metadata_text.is_none()
            && self.release_version.is_none() && self.metadata_images.is_none()
            && self.recovery.as_ref().is_none_or(|recovery|
                self.checkout.is_none() && self.prepared.is_none() && recovery.valid())
    }
    pub(crate) fn workflow_projection(&self) -> Result<crate::github_workflow_edit_protocol::Projection, BridgeError> {
        use crate::github_workflow_edit_protocol::{DOMAIN, Projection};
        if self.domain != EditDomain::GitHubWorkflows || self.recovery.is_some() || self.metadata_text.is_some() || self.release_version.is_some() || self.metadata_images.is_some() || self.checkout.is_some() || self.prepared.is_some() { return Err(BridgeError::protocol()); }
        let detail = self.workflow.as_ref().ok_or_else(BridgeError::protocol)?;
        Ok(Projection { domain: DOMAIN, project_id: self.project_id.clone(), session_id: self.session_id.clone(),
            owner_generation: self.owner_generation.clone(), phase: self.phase, review_remaining_ms: self.review_remaining_ms,
            checkout: detail.checkout.clone(), prepared: detail.prepared.clone(), conflict: detail.conflict.clone(), recovery: detail.recovery.clone(),
            apply_submitted: self.apply_submitted, core_outcome: self.core_outcome.clone(), native_reason: self.native_reason,
            native_finality: self.native_finality, late_settled: self.late_settled })
    }
    pub(crate) fn metadata_text_projection(&self) -> Result<crate::metadata_text_edit_protocol::Projection, BridgeError> {
        use crate::metadata_text_edit_protocol::{DOMAIN, Projection};
        if self.domain != EditDomain::MetadataText || self.recovery.is_some() || self.workflow.is_some() || self.release_version.is_some() || self.metadata_images.is_some() || self.checkout.is_some() || self.prepared.is_some() {
            return Err(BridgeError::protocol());
        }
        let detail = self.metadata_text.as_ref().ok_or_else(BridgeError::protocol)?;
        if detail.recovery.is_some() && (detail.checkout.is_some() || detail.prepared.is_some() || detail.submission.is_some()) { return Err(BridgeError::protocol()); }
        if detail.recovery.is_some() && (detail.platform.is_some() || detail.locale.is_some())
            || detail.recovery.is_none() && !detail.normal_context().is_some_and(|context| context.valid()) { return Err(BridgeError::protocol()); }
        Ok(Projection { domain: DOMAIN, platform: detail.platform, locale: detail.locale.clone(),
            project_id: self.project_id.clone(), session_id: self.session_id.clone(), owner_generation: self.owner_generation.clone(),
            phase: self.phase, review_remaining_ms: self.review_remaining_ms, checkout: detail.checkout.clone(),
            prepared: detail.prepared.clone(), recovery: detail.recovery.clone(), apply_submitted: self.apply_submitted, core_outcome: self.core_outcome.clone(),
            native_reason: self.native_reason, native_finality: self.native_finality, late_settled: self.late_settled })
    }
    pub(crate) fn release_version_projection(&self) -> Result<crate::release_version_edit_protocol::Projection, BridgeError> {
        use crate::release_version_edit_protocol::{DOMAIN, Projection};
        if self.domain != EditDomain::ReleaseVersion || self.recovery.is_some() || self.workflow.is_some() || self.metadata_text.is_some() || self.metadata_images.is_some()
            || self.checkout.is_some() || self.prepared.is_some() { return Err(BridgeError::protocol()); }
        let detail = self.release_version.as_ref().ok_or_else(BridgeError::protocol)?;
        if detail.recovery.is_some() && (detail.checkout.is_some() || detail.prepared.is_some() || detail.submission.is_some()) { return Err(BridgeError::protocol()); }
        Ok(Projection { domain: DOMAIN, project_id: self.project_id.clone(), session_id: self.session_id.clone(),
            owner_generation: self.owner_generation.clone(), phase: self.phase, review_remaining_ms: self.review_remaining_ms,
            checkout: detail.checkout.clone(), prepared: detail.prepared.clone(), recovery: detail.recovery.clone(), apply_submitted: self.apply_submitted,
            core_outcome: self.core_outcome.clone(), native_reason: self.native_reason, native_finality: self.native_finality,
            late_settled: self.late_settled })
    }
    pub(crate) fn metadata_images_projection(&self) -> Result<crate::metadata_images_edit_protocol::Projection, BridgeError> {
        use crate::metadata_images_edit_protocol::{DOMAIN, Projection};
        if self.domain != EditDomain::MetadataImages || self.recovery.is_some() || self.workflow.is_some() || self.metadata_text.is_some()
            || self.release_version.is_some() || self.checkout.is_some() || self.prepared.is_some() {
            return Err(BridgeError::protocol());
        }
        if self.metadata_images.is_none() { return Err(BridgeError::protocol()); }
        Ok(Projection { domain: DOMAIN, project_id: self.project_id.clone(), session_id: self.session_id.clone(),
            owner_generation: self.owner_generation.clone(), phase: self.phase, review_remaining_ms: self.review_remaining_ms,
            apply_submitted: self.apply_submitted, core_outcome: self.core_outcome.clone(), native_reason: self.native_reason,
            native_finality: self.native_finality, late_settled: self.late_settled, details: self.metadata_images.clone() })
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
        if self.schema_version != 1 || self.files.len() != 2 || self.ignore_additions.len() > IGNORE_LINES.len()
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
            && (ignore.action != "create" || self.ignore_additions.len() == IGNORE_LINES.len())
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
// Configuration recovery is a separate closed DATA projection, not a normal
// Save checkout and not evidence of GUI provenance for a legacy init journal.
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
    fn valid(&self, limit: u32, staged: bool) -> bool {
        self.size <= limit && (!staged || self.size > 0) && self.mode <= 0o777
            && self.sha256.len() == 64 && self.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryFile {
    pub id: String, pub path: String, pub action: RecoveryFileAction,
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
            || self.private_cleanup.scope != "inspected-configuration-journal-only"
            || self.private_cleanup.file_count > 16 || self.private_cleanup.directory_count > 1
            || self.private_cleanup.file_count + self.private_cleanup.directory_count > 16 { return false; }
        if self.state != RecoveryState::Recoverable {
            return self.action.is_none() && self.transaction_id.is_none() && self.files.is_empty()
                && self.private_cleanup.file_count == 0 && self.private_cleanup.directory_count == 0;
        }
        if self.action.is_none() || !self.transaction_id.as_deref().is_some_and(token)
            || self.files.len() != 2 || self.private_cleanup.file_count < 2 { return false; }
        self.files.iter().zip([("configuration", "release/mobile-release.json", CONFIG_LIMIT as u32),
            ("root-ignore", ".gitignore", IGNORE_LIMIT)]).all(|(file, (id, path, limit))| {
            let action = if self.action != Some(RecoveryAction::Rollback) || file.after.is_none() { RecoveryFileAction::Preserve }
                else if file.before.is_none() { RecoveryFileAction::Remove } else { RecoveryFileAction::Restore };
            file.id == id && file.path == path && file.action == action
                && file.before.as_ref().is_none_or(|summary| summary.valid(limit, false))
                && file.after.as_ref().is_none_or(|summary| summary.valid(limit, true))
                && (file.before.is_some() || file.after.is_some())
                && (file.before.is_some() || file.after.as_ref().is_some_and(|summary| summary.mode & !0o644 == 0))
                && match (&file.before, &file.after) { (Some(before), Some(after)) => before.mode == after.mode, _ => true }
        })
    }
    pub(crate) fn expected_success(&self) -> Option<Effect> {
        if !self.valid() || self.state != RecoveryState::Recoverable { return None; }
        Some(match self.action? {
            RecoveryAction::CommittedCleanup => Effect::Committed,
            RecoveryAction::Rollback | RecoveryAction::RolledBackCleanup => Effect::RolledBack,
            RecoveryAction::PreparingCleanup => Effect::NotStarted,
        })
    }
}
fn recovery_shape(value: &Value) -> bool {
    keys(value, &["schemaVersion", "kind", "state", "action", "transactionId", "files", "privateCleanup"])
        && keys(&value["privateCleanup"], &["fileCount", "directoryCount", "scope"])
        && value["files"].as_array().is_some_and(|files| files.len() <= 2 && files.iter().all(|file|
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
    pub(crate) fn valid(&self) -> bool {
        self.checkout.as_ref().is_none_or(|checkout| token(&checkout.revision) && checkout.view.valid())
            && self.prepared.as_ref().is_none_or(|prepared| token(&prepared.plan_token)
                && prepared.plan_token != prepared.revision && self.checkout.as_ref().is_some_and(|checkout|
                    prepared.revision == checkout.revision && prepared.view == checkout.view
                        && prepared.view.state == RecoveryState::Recoverable))
    }
    pub(crate) fn terminal_admissible(&self, applied: bool, core: &CoreEditOutcome) -> bool {
        if !self.valid() || !core.valid() || core.effect == Effect::Unchanged
            || applied && self.prepared.is_none() || !applied && core.journal == Journal::Clean { return false; }
        if let Some(checkout) = &self.checkout {
            let view = &checkout.view;
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
            return self.prepared.as_ref().and_then(|prepared| prepared.view.expected_success())
                .is_some_and(|effect| core.effect == effect && core.journal == Journal::Clean && core.resources == ResourceState::Settled);
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
pub struct PrepareConfigurationRecovery { pub session_id: String, pub revision: String, pub intent: RecoveryIntent }

pub enum ChildFrame {
    Opened(Opened), Prepared(PreparedReply), Terminal(u32, TerminalReply),
    ConfigurationRecoveryOpened(RecoveryOpened), ConfigurationRecoveryPrepared(RecoveryPreparedReply),
    WorkflowOpened(crate::github_workflow_edit_protocol::Opened),
    WorkflowPrepared(crate::github_workflow_edit_protocol::PreparedReply),
    WorkflowTerminal(u32, crate::github_workflow_edit_protocol::TerminalReply),
    WorkflowRecoveryOpened(crate::github_workflow_edit_protocol::RecoveryOpened),
    WorkflowRecoveryPrepared(crate::github_workflow_edit_protocol::RecoveryPreparedReply),
    MetadataTextRecoveryOpened(crate::saved_text_recovery_protocol::Opened),
    MetadataTextRecoveryPrepared(crate::saved_text_recovery_protocol::PreparedReply),
    MetadataTextOpened(crate::metadata_text_edit_protocol::Opened),
    MetadataTextPrepared(crate::metadata_text_edit_protocol::PreparedReply),
    MetadataTextTerminal(u32, crate::metadata_text_edit_protocol::TerminalReply),
    ReleaseVersionRecoveryOpened(crate::saved_text_recovery_protocol::Opened),
    ReleaseVersionRecoveryPrepared(crate::saved_text_recovery_protocol::PreparedReply),
    ReleaseVersionOpened(crate::release_version_edit_protocol::Opened),
    ReleaseVersionPrepared(crate::release_version_edit_protocol::PreparedReply),
    ReleaseVersionTerminal(u32, crate::release_version_edit_protocol::TerminalReply),
    MetadataImagesOpened(crate::metadata_images_edit_protocol::Opened),
    MetadataImagesPrepared(crate::metadata_images_edit_protocol::PreparedReply),
    MetadataImagesTerminal(u32, crate::metadata_images_edit_protocol::TerminalReply),
}
impl ChildFrame {
    pub(crate) fn domain(&self) -> EditDomain {
        match self {
            Self::Opened(_) | Self::Prepared(_) | Self::Terminal(..)
                | Self::ConfigurationRecoveryOpened(_) | Self::ConfigurationRecoveryPrepared(_) => EditDomain::Configuration,
            Self::WorkflowOpened(_) | Self::WorkflowPrepared(_) | Self::WorkflowTerminal(..)
                | Self::WorkflowRecoveryOpened(_) | Self::WorkflowRecoveryPrepared(_) => EditDomain::GitHubWorkflows,
            Self::MetadataTextOpened(_) | Self::MetadataTextPrepared(_) | Self::MetadataTextTerminal(..) | Self::MetadataTextRecoveryOpened(_) | Self::MetadataTextRecoveryPrepared(_) => EditDomain::MetadataText,
            Self::ReleaseVersionOpened(_) | Self::ReleaseVersionPrepared(_) | Self::ReleaseVersionTerminal(..) | Self::ReleaseVersionRecoveryOpened(_) | Self::ReleaseVersionRecoveryPrepared(_) => EditDomain::ReleaseVersion,
            Self::MetadataImagesOpened(_) | Self::MetadataImagesPrepared(_) | Self::MetadataImagesTerminal(..) => EditDomain::MetadataImages,
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

pub(crate) fn recovery_request(session: &str, seq: u32, op: &str, params: Value) -> Result<Vec<u8>, BridgeError> {
    if !token(session) || seq > 2 { return Err(BridgeError::invalid()); }
    let legal = match (seq, op) {
        (0, "open") => keys(&params, &["root", "registeredIdentity", "intent"]) && params["intent"] == "recover"
            && params["root"].as_str().is_some_and(|s| s.len() <= 4096)
            && serde_json::from_value::<crate::github_workflow_edit_protocol::RegisteredIdentity>(params["registeredIdentity"].clone()).is_ok_and(|identity| identity.valid()),
        (1, "prepare") => keys(&params, &["revision", "intent"]) && params["intent"] == "recover"
            && params["revision"].as_str().is_some_and(token),
        (2, "apply") => keys(&params, &["planToken", "intent"]) && params["intent"] == "recover"
            && params["planToken"].as_str().is_some_and(token),
        (1 | 2, "discard") => keys(&params, &[]),
        _ => false,
    };
    if !legal { return Err(BridgeError::invalid()); }
    let value = json!({"protocol": PROTOCOL, "session": session, "seq": seq, "op": op, "params": params});
    check_value(&value)?;
    let mut bytes = bounded(&value, REQUEST_LIMIT - 1)?; bytes.push(b'\n'); Ok(bytes)
}

// Intent is captured in the original native Session. A child cannot select its
// decoder by adding/removing a recovery field. Normal decode stays unchanged.
pub(crate) fn decode_with_intent(bytes: &[u8], session: &str, recovery: bool) -> Result<ChildFrame, BridgeError> {
    if !recovery { return decode(bytes, session); }
    if bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &bytes[..bytes.len() - 1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}') || body.iter().any(|b| matches!(*b, b'\r' | b'\n')) { return Err(BridgeError::protocol()); }
    let value = strict_json(body)?;
    if !keys(&value, &["protocol", "session", "seq", "kind", "result"]) || value["protocol"] != PROTOCOL || value["session"] != session { return Err(BridgeError::protocol()); }
    let seq = value["seq"].as_u64().filter(|n| *n <= 2).ok_or_else(BridgeError::protocol)? as u32;
    let raw = &value["result"];
    match value["kind"].as_str() {
        Some("opened") if seq == 0 => {
            if !keys(raw, &["revision", "recovery", "scopeResources"]) || !recovery_shape(&raw["recovery"]) { return Err(BridgeError::protocol()); }
            let result: RecoveryOpened = serde_json::from_value(raw.clone()).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || result.scope_resources != ResourceState::Settled || !result.recovery.valid() { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::ConfigurationRecoveryOpened(result))
        }
        Some("prepared") if seq == 1 => {
            if !keys(raw, &["revision", "planToken", "recovery", "scopeResources"]) || !recovery_shape(&raw["recovery"]) { return Err(BridgeError::protocol()); }
            let result: RecoveryPreparedReply = serde_json::from_value(raw.clone()).map_err(|_| BridgeError::protocol())?;
            if !token(&result.revision) || !token(&result.plan_token) || result.plan_token == result.revision
                || result.scope_resources != ResourceState::Settled || !result.recovery.valid()
                || result.recovery.state != RecoveryState::Recoverable { return Err(BridgeError::protocol()); }
            Ok(ChildFrame::ConfigurationRecoveryPrepared(result))
        }
        Some("terminal") => decode(bytes, session), // Exact existing terminal grammar and outcome bounds.
        _ => Err(BridgeError::protocol()),
    }
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

#[cfg(test)]
mod ignore_vocabulary_tests {
    use super::*;
    fn configuration_recovery_view(action: RecoveryAction) -> RecoveryView {
        let summary = RecoverySummary { size: 2, mode: 0o640, sha256: "a".repeat(64) };
        RecoveryView { schema_version: 1, kind: "recovery".into(), state: RecoveryState::Recoverable,
            action: Some(action), transaction_id: Some("c".repeat(32)),
            files: [("configuration", "release/mobile-release.json"), ("root-ignore", ".gitignore")].into_iter().map(|(id,path)|
                RecoveryFile { id:id.into(),path:path.into(),
                    action:if action == RecoveryAction::Rollback { RecoveryFileAction::Restore } else { RecoveryFileAction::Preserve },
                    before:Some(summary.clone()),after:Some(summary.clone()) }).collect(),
            private_cleanup: RecoveryCleanup { file_count:6,directory_count:1,scope:"inspected-configuration-journal-only".into() } }
    }
    #[test]
    fn configuration_recovery_view_retains_exact_two_file_actions_and_bounds() {
        for (action,effect) in [(RecoveryAction::Rollback,Effect::RolledBack), (RecoveryAction::CommittedCleanup,Effect::Committed),
            (RecoveryAction::RolledBackCleanup,Effect::RolledBack), (RecoveryAction::PreparingCleanup,Effect::NotStarted)] {
            let view = configuration_recovery_view(action);
            assert!(view.valid()); assert_eq!(view.expected_success(),Some(effect));
            for index in 0..2 {
                let limit = if index == 0 { CONFIG_LIMIT as u32 } else { IGNORE_LIMIT };
                let mut at = view.clone(); at.files[index].before.as_mut().unwrap().size=limit;
                at.files[index].after.as_mut().unwrap().size=limit; assert!(at.valid());
                for staged in [false,true] {
                    let mut bad=at.clone();
                    if staged { bad.files[index].after.as_mut().unwrap().size=limit+1; }
                    else { bad.files[index].before.as_mut().unwrap().size=limit+1; }
                    assert!(!bad.valid());
                }
                let mut zero=view.clone(); zero.files[index].before.as_mut().unwrap().size=0; assert!(zero.valid());
                zero.files[index].after.as_mut().unwrap().size=0; assert!(!zero.valid());
                let mut created=view.clone(); created.files[index].before=None;
                created.files[index].action=if action==RecoveryAction::Rollback { RecoveryFileAction::Remove } else { RecoveryFileAction::Preserve };
                assert!(created.valid()); created.files[index].after.as_mut().unwrap().mode=0o601; assert!(!created.valid());
                let mut preserved=view.clone(); preserved.files[index].after=None;
                preserved.files[index].action=RecoveryFileAction::Preserve; assert!(preserved.valid());
            }
            for change in 0..12 {
                let mut bad=view.clone();
                match change {
                    0=>bad.files.swap(0,1), 1=>bad.files[0].id="preflight".into(),
                    2=>bad.files[0].path=".github/workflows/mobile-preflight.yml".into(),
                    3=>bad.private_cleanup.scope="inspected-workflow-journal-only".into(),
                    4=>bad.private_cleanup.directory_count=2, 5=>bad.private_cleanup.file_count=16,
                    6=>bad.transaction_id=Some("X".repeat(32)), 7=>bad.files[0].after.as_mut().unwrap().sha256="A".repeat(64),
                    8=>bad.files[0].before.as_mut().unwrap().mode=0o4640,
                    9=>bad.files[0].after.as_mut().unwrap().mode=0o600,
                    10=>bad.files[0].action=if action==RecoveryAction::Rollback {RecoveryFileAction::Preserve} else {RecoveryFileAction::Restore},
                    _=>{bad.files[0].before=None;bad.files[0].after=None;},
                }
                assert!(!bad.valid(),"{action:?}/{change}");
            }
        }
        for state in [RecoveryState::Idle,RecoveryState::Conflict] {
            let mut view=configuration_recovery_view(RecoveryAction::Rollback);
            view.state=state;view.action=None;view.transaction_id=None;view.files.clear();
            view.private_cleanup.file_count=0;view.private_cleanup.directory_count=0;
            assert!(view.valid());assert_eq!(view.expected_success(),None);
            view.private_cleanup.file_count=1;assert!(!view.valid());
        }
    }
    #[test]
    fn configuration_recovery_wire_is_closed_and_uses_retained_intent() {
        let session="0".repeat(32);let revision="1".repeat(32);let plan="2".repeat(32);
        let identity=json!({"device":"1","inode":"2","mode":0o40700,"uid":1000,"gid":1000});
        let open=json!({"root":"/inert/project","registeredIdentity":identity,"intent":"recover"});
        let prepare=json!({"revision":revision,"intent":"recover"});
        let apply=json!({"planToken":plan,"intent":"recover"});
        for (seq,op,params) in [(0,"open",open.clone()),(1,"prepare",prepare),(2,"apply",apply)] {
            assert!(recovery_request(&session,seq,op,params.clone()).is_ok());
            assert!(request(&session,seq,op,params.clone()).is_err());
            let mut missing=params.clone();missing.as_object_mut().unwrap().remove("intent");
            assert!(recovery_request(&session,seq,op,missing).is_err());
            for value in [Value::Null,json!(false),json!("edit"),json!("Recover"),json!(["recover"])] {
                let mut bad=params.clone();bad["intent"]=value;assert!(recovery_request(&session,seq,op,bad).is_err());
            }
            for key in ["force","files","draft","expectedBase","projectId"] {
                let mut bad=params.clone();bad[key]=Value::Null;assert!(recovery_request(&session,seq,op,bad).is_err());
            }
        }
        for bad_identity in [json!({}),json!({"device":"1","inode":"0","mode":0o40700,"uid":1000,"gid":1000}),
            json!({"device":"01","inode":"2","mode":0o40700,"uid":1000,"gid":1000}),
            json!({"device":"1","inode":"2","mode":0o100600,"uid":1000,"gid":1000})] {
            let mut bad=open.clone();bad["registeredIdentity"]=bad_identity;assert!(recovery_request(&session,0,"open",bad).is_err());
        }
        for seq in [1,2] { assert_eq!(recovery_request(&session,seq,"discard",json!({})).unwrap(),request(&session,seq,"discard",json!({})).unwrap()); }
        let frame=|seq,kind,result| { let mut bytes=serde_json::to_vec(&json!({"protocol":PROTOCOL,"session":session,"seq":seq,"kind":kind,"result":result})).unwrap();bytes.push(b'\n');bytes };
        let view=serde_json::to_value(configuration_recovery_view(RecoveryAction::Rollback)).unwrap();
        let opened=json!({"revision":revision,"recovery":view,"scopeResources":"settled"});
        let prepared=json!({"revision":revision,"planToken":plan,"recovery":view,"scopeResources":"settled"});
        assert!(matches!(decode_with_intent(&frame(0,"opened",opened.clone()),&session,true),Ok(ChildFrame::ConfigurationRecoveryOpened(_))));
        assert!(matches!(decode_with_intent(&frame(1,"prepared",prepared.clone()),&session,true),Ok(ChildFrame::ConfigurationRecoveryPrepared(_))));
        assert!(decode_with_intent(&frame(0,"opened",opened.clone()),&session,false).is_err());
        assert!(decode_with_intent(&frame(1,"prepared",prepared.clone()),&session,false).is_err());
        let normal=frame(0,"opened",json!({"revision":revision,"base":null,"scopeResources":"settled"}));
        assert!(matches!(decode_with_intent(&normal,&session,false),Ok(ChildFrame::Opened(_))));
        assert!(decode_with_intent(&normal,&session,true).is_err());
        for field in ["action","transactionId","files","privateCleanup"] {
            let mut bad=opened.clone();bad["recovery"].as_object_mut().unwrap().remove(field);
            assert!(decode_with_intent(&frame(0,"opened",bad),&session,true).is_err());
        }
        let mut extra=opened.clone();extra["recovery"]["root"]=json!("/elsewhere");
        assert!(decode_with_intent(&frame(0,"opened",extra),&session,true).is_err());
        let mut unknown=opened;unknown["scopeResources"]=json!("unknown");
        assert!(decode_with_intent(&frame(0,"opened",unknown),&session,true).is_err());
        let mut same=prepared;same["planToken"]=json!(revision);
        assert!(decode_with_intent(&frame(1,"prepared",same),&session,true).is_err());
        let pending=json!({"planToken":null,"effect":"committed","journal":"recovery_required","resources":"settled","reason":"pending_state"});
        assert!(matches!(decode_with_intent(&frame(0,"terminal",pending.clone()),&session,true),Ok(ChildFrame::Terminal(0,_))));
        let mut lie=pending;lie["reason"]=json!("none");
        assert!(decode_with_intent(&frame(0,"terminal",lie),&session,true).is_err());
        let mut extra_line=normal;extra_line.push(b'\n');assert!(decode_with_intent(&extra_line,&session,true).is_err());
    }
    fn proposed() -> PreparedConfigView {
        let assurance = json!({"basis":"schema-policy","projectCodeExecuted":false,"toolsProbed":false,"credentialsRead":false,
            "gitObserved":false,"storeContacted":false,"writesPerformed":false,"releaseReadiness":"unknown"});
        PreparedConfigView { schema_version:1,
            files:vec![FileView { path:"release/mobile-release.json".into(),action:"create".into(),before_bytes:None,after_bytes:2 },
                FileView { path:".gitignore".into(),action:"create".into(),before_bytes:None,after_bytes:256 }],
            create_release_directory:true,rewrites_config_formatting:false,
            ignore_additions:IGNORE_LINES.iter().map(|line| (*line).to_owned()).collect(),
            preview:json!({"schemaVersion":1,"validation":{"valid":true,"state":"format-valid","issues":[],"requirements":[],"assurance":assurance.clone()},
                "comparison":{"baseProvided":false,"kind":"proposed-create","state":"complete","semanticallyChanged":true,"counts":{"added":0,"changed":0,"removed":0},"changes":[],"unreviewedCount":0},
                "fields":[],"assurance":assurance}) }
    }
    #[test]
    fn image_ignore_prerequisites_extend_only_the_fixed_thirteen_rule_vocabulary() {
        let original = proposed(); assert!(original.valid());
        assert_eq!(&IGNORE_LINES[4..7],&[".mobile-release-metadata-text-prepare/",".mobile-release-metadata-text/",".mobile-release-metadata-text-cleanup/"]);
        assert_eq!(&IGNORE_LINES[7..10], &[".mobile-release-version-prepare/", ".mobile-release-version/", ".mobile-release-version-cleanup/"]);
        assert_eq!(&IGNORE_LINES[10..], &[".mobile-release-metadata-images-prepare/", ".mobile-release-metadata-images/", ".mobile-release-metadata-images-cleanup/"]);
        let mut stale_images = original.clone(); stale_images.ignore_additions.truncate(10); assert!(!stale_images.valid());
        let mut stale = original.clone(); stale.ignore_additions.truncate(7); assert!(!stale.valid());
        for rule in ["metadata/", "!release/private/", ".mobile-release-other/"] {
            let mut bad = original.clone(); bad.ignore_additions[4] = rule.into(); assert!(!bad.valid());
        }
        let mut bad = original.clone(); bad.ignore_additions.truncate(4); assert!(!bad.valid());
        let mut bad = original.clone(); bad.ignore_additions.swap(4,5); assert!(!bad.valid());
        let mut bad = original.clone(); bad.files.push(FileView { path:"release/metadata/android/en-US/title.txt".into(),action:"create".into(),before_bytes:None,after_bytes:1 });
        assert!(!bad.valid()); // Configuration still has exactly two destinations.
        let mut bad = original; bad.files[1].path = "release/metadata/android/en-US/title.txt".into(); assert!(!bad.valid());
    }
}
