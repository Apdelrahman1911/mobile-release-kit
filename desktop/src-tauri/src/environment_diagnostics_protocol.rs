//! Closed DATA for one explicitly requested, finite build-tool observation.
//! Neither this protocol nor a terminal frame grants native execution/finality.
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{edit_protocol::{bounded, token}, error::BridgeError, protocol::{check_value, strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-environment-diagnostics/1";
pub(crate) const EVENT: &str = "environment-diagnostics-state-changed";
pub(crate) const REQUEST_LIMIT: usize = 1024 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024; // Both frames AND framing.
pub(crate) const STATUS_LIMIT: usize = 64 * 1024;
const DRAFT_LIMIT: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform { Android, Ios }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Operation { Build }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) platform: Platform, pub(crate) operation: Operation,
}
impl Context {
    fn valid(&self) -> bool {
        valid_id(&self.project_id) && self.draft_revision < u32::MAX && self.baseline_generation < u32::MAX
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start {
    pub(crate) project_id: String, pub(crate) draft: Value, pub(crate) draft_revision: u32,
    pub(crate) baseline_generation: u32, pub(crate) platform: Platform, pub(crate) operation: Operation,
}
impl Start {
    pub(crate) fn context(&self) -> Context { Context { project_id: self.project_id.clone(), draft_revision: self.draft_revision,
        baseline_generation: self.baseline_generation, platform: self.platform, operation: self.operation } }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) run_id: String, pub(crate) owner_generation: String }
fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)))
}
pub(crate) fn invalid() -> BridgeError { BridgeError::new("environment_diagnostics_invalid", "The build-tool diagnostics request is invalid.") }
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    if !keys(value, &["projectId", "draft", "draftRevision", "baselineGeneration", "platform", "operation"]) { return Err(invalid()); }
    check_value(value).map_err(|_| invalid())?;
    bounded(value, REQUEST_LIMIT - 1).map_err(|_| invalid())?;
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    if !input.context().valid() || !input.draft.is_object() { return Err(invalid()); }
    bounded(&input.draft, DRAFT_LIMIT).map_err(|_| invalid())?;
    Ok(input)
}
pub(crate) fn cancel(value: &Value) -> Result<Cancel, BridgeError> {
    if !keys(value, &["runId", "ownerGeneration"]) { return Err(invalid()); }
    let input = Cancel::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.run_id) || !token(&input.owner_generation) { return Err(invalid()); }
    Ok(input)
}
pub(crate) fn status_request(value: &Value) -> Result<(), BridgeError> {
    if keys(value, &[]) { Ok(()) } else { Err(invalid()) }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Host { Linux, Macos }
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
    pub(crate) fn host(self) -> Host { match self { Self::LinuxX64 | Self::LinuxArm64 => Host::Linux, _ => Host::Macos } }
}
fn native_path(path: &Path) -> Option<&str> {
    let text = path.to_str()?;
    if text.len() > 4096 || !text.starts_with('/') || text.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}' || c == '\\') { return None; }
    if text != "/" {
        let parts: Vec<_> = text[1..].split('/').collect();
        if parts.len() > 128 || parts.iter().any(|p| p.is_empty() || *p == "." || *p == ".." || p.len() > 255) { return None; }
    }
    Some(text)
}
pub(crate) fn request(run: &str, generation: &str, context: &Context, draft: &Value,
    profile: Profile, project: &Path, cwd: &Path) -> Result<Vec<u8>, BridgeError> {
    if !token(run) || !token(generation) || !context.valid() || !draft.is_object() { return Err(invalid()); }
    bounded(draft, DRAFT_LIMIT).map_err(|_| invalid())?;
    let value = json!({"protocol": PROTOCOL, "runId": run, "ownerGeneration": generation,
        "context": context, "draft": draft,
        "native": {"profile": profile, "projectRoot": native_path(project).ok_or_else(invalid)?, "cwd": native_path(cwd).ok_or_else(invalid)?}});
    check_value(&value).map_err(|_| invalid())?;
    let mut bytes = bounded(&value, REQUEST_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n'); Ok(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome { Complete, Partial, Failed, Cancelled, TimedOut, Unavailable }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CheckId { DeveloperSelection, Git, Java, Javac, Xcode }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CheckState { NotRun, Attempted, Completed }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CheckReason {
    InvalidDraft, PlatformDisabled, HostMismatch, UnsupportedHost, MissingInSupportedLookup,
    UnsupportedInstallation, UnselectedInstallation, FullXcodeNotSelected, Stopped,
    CommandIncomplete, BindingChanged, Cancelled, TimedOut,
    Observed, NonzeroExit, VersionUnrecognized, SelectionUnrecognized,
}
impl CheckReason {
    fn state(self) -> CheckState { match self {
        Self::CommandIncomplete | Self::BindingChanged | Self::Cancelled | Self::TimedOut => CheckState::Attempted,
        Self::Observed | Self::NonzeroExit | Self::VersionUnrecognized | Self::SelectionUnrecognized => CheckState::Completed,
        _ => CheckState::NotRun,
    } }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum BaselineKind { WorkflowReference, ExactPin, NoLocalPolicy }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Baseline { kind: BaselineKind, version: Option<String>, build: Option<String> }
fn version(text: &str) -> bool {
    !text.is_empty() && text.len() <= 64 && text.as_bytes()[0].is_ascii_digit()
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}
fn digits(bytes: &[u8], start: usize, maximum: usize) -> Option<usize> {
    let count = bytes.get(start..)?.iter().take_while(|b| b.is_ascii_digit()).count();
    (count > 0 && count <= maximum).then_some(start + count)
}
fn role_version(role: CheckId, text: &str) -> bool {
    if !version(text) { return false; }
    let bytes = text.as_bytes();
    let Some(mut at) = digits(bytes, 0, 3) else { return false; };
    match role {
        CheckId::Git => {
            if bytes.get(at) != Some(&b'.') { return false; }
            let Some(second) = digits(bytes, at + 1, 3) else { return false; };
            let suffix = |at: usize| {
                let tail = &bytes[at..];
                tail.is_empty() || (2..=42).contains(&tail.len()) && matches!(tail[0], b'.' | b'-')
                    && tail[1].is_ascii_alphanumeric() && tail[2..].iter().all(|b| b.is_ascii_alphanumeric() || b".+-".contains(b))
            };
            suffix(second) || bytes.get(second) == Some(&b'.') && digits(bytes, second + 1, 3).is_some_and(suffix)
        }
        CheckId::Java | CheckId::Javac => {
            let mut count = 0;
            while count < 3 && bytes.get(at).is_some_and(|b| matches!(*b, b'.' | b'_')) {
                let Some(next) = digits(bytes, at + 1, 6) else { return false; };
                at = next; count += 1;
            }
            let tail = &bytes[at..];
            tail.is_empty() || (2..=34).contains(&tail.len()) && matches!(tail[0], b'+' | b'-')
                && tail[1].is_ascii_alphanumeric() && tail[2..].iter().all(|b| b.is_ascii_alphanumeric() || b".+_-".contains(b))
        }
        CheckId::Xcode => {
            if bytes.get(at) != Some(&b'.') { return false; }
            let Some(second) = digits(bytes, at + 1, 3) else { return false; };
            second == bytes.len() || bytes.get(second) == Some(&b'.') && digits(bytes, second + 1, 3) == Some(bytes.len())
        }
        CheckId::DeveloperSelection => false,
    }
}
fn build(text: &str) -> bool {
    let bytes = text.as_bytes();
    let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if !(1..=3).contains(&digits) || !bytes.get(digits).is_some_and(u8::is_ascii_uppercase) { return false; }
    let tail = &bytes[digits + 1..];
    let count = tail.iter().take_while(|b| b.is_ascii_digit()).count();
    (1..=6).contains(&count) && (count == tail.len() || count + 1 == tail.len() && tail[count].is_ascii_lowercase())
}
impl Baseline {
    fn valid(&self, role: CheckId) -> bool {
        // Core toolchain_policy remains the sole version authority. Rust joins
        // observed Xcode with the supplied exact baseline, never a copied pin.
        match role {
            CheckId::Java | CheckId::Javac => self.kind == BaselineKind::WorkflowReference
                && self.version.as_deref().is_some_and(version) && self.build.is_none(),
            CheckId::Xcode => self.kind == BaselineKind::ExactPin && self.version.as_deref().is_some_and(version)
                && self.build.as_deref().is_some_and(build),
            _ => self.kind == BaselineKind::NoLocalPolicy && self.version.is_none() && self.build.is_none(),
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Assessment { Match, Mismatch, NoLocalPolicy, NotAssessed }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum SelectionStage { SelectorOutput, SelectionPath, Root, Applications, Application, Contents, Developer,
    Library, LibraryDeveloper, CommandLineTools, Alias }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum SelectionReason { StderrPresent, ByteShape, LineShape, Utf8Invalid, PathShape, AppName, PathDepth, ProjectOverlap,
    NamespaceMissing, NamespaceInaccessible, DirectoryKind, DirectoryOwner, DirectoryWorldWrite, DirectoryGroupWrite,
    AliasDisallowed, AliasKind, AliasOwner, TargetBytes, TargetEncoding, TargetShape, IdentityChanged }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SelectionDiagnostic { stage: SelectionStage, reason: SelectionReason }
impl SelectionDiagnostic {
    fn valid(&self) -> bool {
        use SelectionReason::*;
        let directory = matches!(self.reason, NamespaceMissing | NamespaceInaccessible | DirectoryKind | DirectoryOwner
            | DirectoryWorldWrite | DirectoryGroupWrite);
        let compatible = match self.stage {
            SelectionStage::SelectorOutput => matches!(self.reason, StderrPresent | ByteShape | LineShape | Utf8Invalid | PathShape | AppName),
            SelectionStage::SelectionPath => matches!(self.reason, PathDepth | ProjectOverlap),
            SelectionStage::Application => directory || self.reason == AliasDisallowed,
            SelectionStage::Alias => matches!(self.reason, NamespaceMissing | NamespaceInaccessible | AliasKind | AliasOwner
                | TargetBytes | TargetEncoding | TargetShape | IdentityChanged),
            _ => directory,
        };
        compatible && serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() < 160)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Check {
    id: CheckId, state: CheckState, reason: CheckReason, version: Option<String>, build: Option<String>,
    return_code: Option<i32>, baseline: Baseline, assessment: Assessment, help: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selection_diagnostic: Option<SelectionDiagnostic>,
}
impl Check {
    fn valid(&self, expected: CheckId) -> bool {
        if self.id != expected || self.reason.state() != self.state || !self.baseline.valid(self.id)
            || self.selection_diagnostic.as_ref().is_some_and(|detail| self.id != CheckId::DeveloperSelection
                || self.state != CheckState::Completed || self.reason != CheckReason::SelectionUnrecognized
                || self.return_code != Some(0) || !detail.valid())
            || self.reason == CheckReason::FullXcodeNotSelected && self.id != CheckId::Xcode
            || self.help.trim().is_empty() || self.help.len() > 1024 || self.help.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
            || self.version.as_deref().is_some_and(|v| !role_version(self.id, v)) || self.build.as_deref().is_some_and(|v| !build(v)) { return false; }
        let empty = self.version.is_none() && self.build.is_none() && self.assessment == Assessment::NotAssessed;
        if self.state != CheckState::Completed { return self.return_code.is_none() && empty; }
        let Some(code) = self.return_code else { return false; };
        if (self.reason == CheckReason::NonzeroExit) != (code != 0) { return false; }
        if self.reason != CheckReason::Observed {
            return empty && (self.reason == CheckReason::SelectionUnrecognized)
                == (self.id == CheckId::DeveloperSelection && self.reason != CheckReason::NonzeroExit);
        }
        match self.id {
            CheckId::DeveloperSelection => empty,
            CheckId::Xcode => self.version.is_some() && self.build.is_some() && self.assessment
                == if self.version == self.baseline.version && self.build == self.baseline.build { Assessment::Match } else { Assessment::Mismatch },
            _ => self.version.is_some() && self.build.is_none() && self.assessment == Assessment::NoLocalPolicy,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CoreStop { None, Cancelled, TimedOut }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Lifetime {
    complete: bool, fatal: bool, contained: bool, command_dispatched: Option<bool>, commands: u32,
    input_closed: bool, handlers_restored: bool, tool_descriptors_closed: bool, stop_observed: CoreStop,
}
impl Lifetime {
    fn consistent(&self) -> bool { self.fatal || self.complete && self.contained && self.command_dispatched.is_some() }
    pub(crate) fn settled(&self) -> bool {
        self.complete && !self.fatal && self.contained && self.command_dispatched.is_some()
            && self.input_closed && self.handlers_restored && self.tool_descriptors_closed
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Assurance {
    basis: String, tools_attempted: bool, project_code_executed: bool, project_files_read: bool,
    repository_observed: bool, sdk_inspected: bool, credentials_read: bool, store_contacted: bool,
    dependency_completeness: String, release_readiness: String, tool_cache_effects: String,
}
impl Assurance {
    fn valid(&self, attempts: u32) -> bool {
        self.basis == "local-tool-observation" && self.tools_attempted == (attempts > 0)
            && !self.project_code_executed && !self.project_files_read && !self.repository_observed
            && !self.sdk_inspected && !self.credentials_read && !self.store_contacted
            && self.dependency_completeness == "unknown" && self.release_readiness == "unknown" && self.tool_cache_effects == "possible"
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Terminal {
    schema_version: u32, policy_version: String, context: Context, host_platform: Host,
    pub(crate) outcome: Outcome, checks: Vec<Check>, commands_attempted: u32,
    pub(crate) lifetime: Lifetime, assurance: Assurance,
}
fn roster(host: Host, platform: Platform) -> &'static [CheckId] {
    use CheckId::*;
    match (host, platform) {
        (Host::Linux, Platform::Android) => &[Git, Java, Javac],
        (Host::Linux, Platform::Ios) => &[Git, Xcode],
        (Host::Macos, Platform::Android) => &[DeveloperSelection, Git, Java, Javac],
        (Host::Macos, Platform::Ios) => &[DeveloperSelection, Git, Xcode],
    }
}
impl Terminal {
    pub(crate) fn completed_rows(&self) -> usize { self.checks.iter().filter(|c| c.state == CheckState::Completed).count() }
    fn valid(&self, context: &Context, host: Host) -> bool {
        let roles = roster(host, context.platform);
        let completed = self.completed_rows();
        if self.schema_version != 1 || self.policy_version != "environment-diagnostics-v1" || self.context != *context
            || !self.context.valid() || self.host_platform != host || self.checks.len() != roles.len()
            || !self.checks.iter().zip(roles).all(|(check, role)| check.valid(*role)) || self.commands_attempted > 4
            || self.commands_attempted as usize != self.checks.iter().filter(|c| c.state != CheckState::NotRun).count()
            || self.lifetime.commands > self.commands_attempted || completed > self.lifetime.commands as usize
            || completed > 0 && self.lifetime.command_dispatched != Some(true)
            || !self.lifetime.consistent() || !self.assurance.valid(self.commands_attempted)
            || host == Host::Linux && context.platform == Platform::Ios && self.commands_attempted != 0 { return false; }
        // A completed observation requires an actual completed ordinary-owner
        // record even when a later command has left the aggregate ledger fatal.
        // Only an explicitly observed STOP permits that attempted-row label;
        // a later STOP need not rewrite historical command-incomplete rows.
        if self.checks.iter().any(|c| c.state == CheckState::Attempted && match c.reason {
            CheckReason::Cancelled => self.lifetime.stop_observed != CoreStop::Cancelled,
            CheckReason::TimedOut => self.lifetime.stop_observed != CoreStop::TimedOut,
            _ => false,
        }) { return false; }
        if self.checks.iter().any(|c| c.reason == CheckReason::HostMismatch) && !(host == Host::Linux && context.platform == Platform::Ios) { return false; }
        if let Some(global) = self.checks.iter().find(|c| matches!(c.reason, CheckReason::InvalidDraft | CheckReason::PlatformDisabled
            | CheckReason::HostMismatch | CheckReason::UnsupportedHost)).map(|c| c.reason) {
            if self.commands_attempted != 0 || self.checks.iter().any(|c| c.reason != global) { return false; }
        }
        match self.outcome {
            Outcome::Complete | Outcome::Unavailable => self.lifetime.settled() && self.lifetime.stop_observed == CoreStop::None
                && self.checks.iter().all(|c| c.state != CheckState::Attempted && c.reason != CheckReason::Stopped)
                && (self.outcome == Outcome::Unavailable) == (self.commands_attempted == 0)
                && self.lifetime.commands == self.commands_attempted && self.lifetime.command_dispatched == Some(self.commands_attempted > 0),
            Outcome::Partial | Outcome::Failed => (self.outcome == Outcome::Partial) == (completed > 0)
                && self.lifetime.stop_observed == CoreStop::None,
            Outcome::Cancelled => self.lifetime.stop_observed == CoreStop::Cancelled,
            Outcome::TimedOut => self.lifetime.stop_observed == CoreStop::TimedOut,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Accepted { schema_version: u32, context: Context, host_platform: Host }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope { protocol: String, run_id: String, owner_generation: String, seq: u32, kind: String, result: Value }
pub(crate) enum Frame { Accepted, Terminal(Terminal) }
pub(crate) fn decode(bytes: &[u8], run: &str, generation: &str, context: &Context, host: Host) -> Result<Frame, BridgeError> {
    if bytes.len() < 3 || bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") || bytes[0] != b'{'
        || bytes[bytes.len() - 2] != b'}' || bytes[..bytes.len() - 1].iter().any(|b| *b == b'\r' || *b == b'\n') { return Err(BridgeError::protocol()); }
    let value = strict_json(&bytes[..bytes.len() - 1])?;
    let envelope = Envelope::deserialize(&value).map_err(|_| BridgeError::protocol())?;
    if envelope.protocol != PROTOCOL || envelope.run_id != run || envelope.owner_generation != generation
        || !token(&envelope.run_id) || !token(&envelope.owner_generation) { return Err(BridgeError::protocol()); }
    match (envelope.seq, envelope.kind.as_str()) {
        (0, "accepted") => {
            let accepted = Accepted::deserialize(&envelope.result).map_err(|_| BridgeError::protocol())?;
            if accepted.schema_version != 1 || accepted.context != *context || !accepted.context.valid() || accepted.host_platform != host { return Err(BridgeError::protocol()); }
            Ok(Frame::Accepted)
        }
        (1, "terminal") => {
            let rows = envelope.result.get("checks").and_then(Value::as_array).ok_or_else(BridgeError::protocol)?;
            // Nullable fields are REQUIRED, not serde's omitted Option default.
            if rows.iter().any(|r| (!keys(r, &["id", "state", "reason", "version", "build", "returnCode", "baseline", "assessment", "help"])
                && !keys(r, &["id", "state", "reason", "version", "build", "returnCode", "baseline", "assessment", "help", "selectionDiagnostic"]))
                || !r.get("baseline").is_some_and(|b| keys(b, &["kind", "version", "build"])))
                || !envelope.result.get("lifetime").is_some_and(|l| keys(l, &["complete", "fatal", "contained", "commandDispatched", "commands", "inputClosed", "handlersRestored", "toolDescriptorsClosed", "stopObserved"])) { return Err(BridgeError::protocol()); }
            let terminal = Terminal::deserialize(&envelope.result).map_err(|_| BridgeError::protocol())?;
            if !terminal.valid(context, host) { return Err(BridgeError::protocol()); }
            Ok(Frame::Terminal(terminal))
        }
        _ => Err(BridgeError::protocol()),
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { Starting, Checking, Stopping, Settled, RetainedUnknown }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Finality { Pending, Settled, Unknown }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason { None, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable, CommandFailed, CleanupUnknown }
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Availability { Available, Busy, Shutdown, CleanupUnknown, DocumentLost, UnsupportedPlatform, RuntimeUnqualified }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Projection {
    pub(crate) run_id: String, pub(crate) owner_generation: String, pub(crate) context: Context,
    pub(crate) phase: Phase, pub(crate) outcome: Option<Outcome>, pub(crate) finality: Finality,
    pub(crate) reason: Reason, pub(crate) result: Option<Terminal>,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Capability { pub(crate) available: bool, pub(crate) reason: Availability }
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32, pub(crate) status_revision: u32, pub(crate) capability: Capability,
    pub(crate) active: Option<Projection>, pub(crate) last_terminal: Option<Projection>,
}

#[cfg(test)]
pub(crate) mod tests {
    // Inert bounded DATA only: no runtime, process, descriptor or tool fixture.
    use super::*;
    fn context() -> Context { Context { project_id: "project-1".into(), draft_revision: 1, baseline_generation: 2,
        platform: Platform::Ios, operation: Operation::Build } }
    fn frame(kind: &str, seq: u32, result: Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"runId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"seq":seq,"kind":kind,"result":result})).unwrap();
        bytes.push(b'\n'); bytes
    }
    fn accepted() -> Vec<u8> { frame("accepted", 0, json!({"schemaVersion":1,"context":context(),"hostPlatform":"linux"})) }
    pub(crate) fn terminal(context: &Context) -> Value {
        let checks: Vec<Value> = ["git", "java", "javac"].iter().map(|id| json!({"id":id,"state":"completed","reason":"observed",
            "version":if *id == "git" { "2.43.0" } else { "21.0.1" },"build":null,"returnCode":0,
            "baseline":if *id == "git" { json!({"kind":"no-local-policy","version":null,"build":null}) }
                else { json!({"kind":"workflow-reference","version":"21","build":null}) },
            "assessment":"no-local-policy","help":"Fixed core explanation"})).collect();
        json!({"schemaVersion":1,"policyVersion":"environment-diagnostics-v1","context":context,"hostPlatform":"linux",
            "outcome":"complete","checks":checks,"commandsAttempted":3,
            "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":3,
                "inputClosed":true,"handlersRestored":true,"toolDescriptorsClosed":true,"stopObserved":"none"},
            "assurance":{"basis":"local-tool-observation","toolsAttempted":true,"projectCodeExecuted":false,"projectFilesRead":false,
                "repositoryObserved":false,"sdkInspected":false,"credentialsRead":false,"storeContacted":false,
                "dependencyCompleteness":"unknown","releaseReadiness":"unknown","toolCacheEffects":"possible"}})
    }
    pub(crate) fn terminal_frame(context: &Context) -> Frame {
        decode(&frame("terminal",1,terminal(context)), &"a".repeat(32), &"b".repeat(32), context, Host::Linux).unwrap()
    }
    #[test]
    fn native_inputs_cannot_be_smuggled_through_start_or_cancel() {
        let value = json!({"projectId":"project-1","draft":{},"draftRevision":0,"baselineGeneration":0,"platform":"android","operation":"build"});
        assert!(start(&value).is_ok());
        for key in ["root", "native", "cwd", "env", "argv", "profile"] {
            let mut bad = value.clone(); bad[key] = json!("injected"); assert!(start(&bad).is_err());
        }
        for (key, data) in [("operation",json!("artifact-validation")), ("draftRevision",json!(u32::MAX)), ("draft",json!([]))] {
            let mut bad = value.clone(); bad[key] = data; assert!(start(&bad).is_err());
        }
        let mut too_big = value; too_big["draft"] = json!({"padding":"x".repeat(DRAFT_LIMIT)}); assert!(start(&too_big).is_err());
        assert!(cancel(&json!({"runId":"a".repeat(32),"ownerGeneration":"b".repeat(32)})).is_ok());
        assert!(cancel(&json!({"runId":"a".repeat(32)})).is_err());
        assert!(status_request(&json!({})).is_ok()); assert!(status_request(&json!({"retry":true})).is_err());
    }
    #[test]
    fn strict_transport_checks_identity_framing_and_closed_keys() {
        let decode_one = |bytes: &[u8]| decode(bytes, &"a".repeat(32), &"b".repeat(32), &context(), Host::Linux);
        assert!(matches!(decode_one(&accepted()), Ok(Frame::Accepted)));
        let mut stale = context(); stale.baseline_generation += 1;
        assert!(decode(&accepted(), &"a".repeat(32), &"b".repeat(32), &stale, Host::Linux).is_err());
        assert!(decode(&accepted(), &"a".repeat(32), &"c".repeat(32), &context(), Host::Linux).is_err());
        assert!(decode_one(&frame("accepted",1,json!({"schemaVersion":1,"context":context(),"hostPlatform":"linux"}))).is_err());
        let mut missing_lf = accepted(); missing_lf.pop(); assert!(decode_one(&missing_lf).is_err());
        let mut tail = accepted(); tail.extend_from_slice(b"{}\n"); assert!(decode_one(&tail).is_err());
        let duplicate = String::from_utf8(accepted()).unwrap().replacen("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1", 1);
        assert!(decode_one(duplicate.as_bytes()).is_err());
        assert!(decode_one(&frame("accepted",0,json!({"schemaVersion":1,"context":context(),"hostPlatform":"linux","raw":"private"}))).is_err());
    }
    #[test]
    fn xcode_matches_complete_baseline_pair_not_substring_or_version_alone() {
        let base = json!({"id":"xcode","state":"completed","reason":"observed","version":"26.3","build":"17C529","returnCode":0,
            "baseline":{"kind":"exact-pin","version":"26.3","build":"17C529"},"assessment":"match","help":"Fixed help"});
        assert!(Check::deserialize(&base).unwrap().valid(CheckId::Xcode));
        for (key, value) in [("build",json!("17C530")),("returnCode",json!(1)),("version",json!(null)),("reason",json!("command-incomplete"))] {
            let mut bad = base.clone(); bad[key] = value; assert!(!Check::deserialize(&bad).unwrap().valid(CheckId::Xcode));
        }
        let mut different = base; different["build"] = json!("17C530"); different["assessment"] = json!("mismatch");
        assert!(Check::deserialize(&different).unwrap().valid(CheckId::Xcode));
    }
    #[test]
    fn native_paths_are_retained_data_not_normalized_renderer_authority() {
        for bad in ["relative", "/a/../b", "/a//b", "/a/", "/a\\b", "/a\nb"] { assert!(native_path(Path::new(bad)).is_none()); }
        let bytes = request(&"a".repeat(32), &"b".repeat(32), &context(), &json!({}), Profile::LinuxX64, Path::new("/selected"), Path::new("/neutral")).unwrap();
        let data = strict_json(&bytes[..bytes.len()-1]).unwrap();
        assert_eq!(data["native"], json!({"profile":"linux-gnu-x86_64","projectRoot":"/selected","cwd":"/neutral"}));
    }
    #[test]
    fn terminal_ledger_scope_and_accounting_are_not_optional_success_flags() {
        let context = Context { platform: Platform::Android, ..context() }; let original = terminal(&context);
        let parsed = |value: Value| decode(&frame("terminal",1,value), &"a".repeat(32), &"b".repeat(32), &context, Host::Linux);
        assert!(matches!(parsed(original.clone()), Ok(Frame::Terminal(_))));
        for (key, value) in [("complete",json!(false)),("fatal",json!(true)),("contained",json!(false)),("commandDispatched",Value::Null),
            ("commands",json!(2)),("inputClosed",json!(false)),("handlersRestored",json!(false)),("toolDescriptorsClosed",json!(false)),("stopObserved",json!("cancelled"))] {
            let mut bad = original.clone(); bad["lifetime"][key] = value; assert!(parsed(bad).is_err(), "{key}");
        }
        for key in ["commandDispatched","inputClosed","handlersRestored","toolDescriptorsClosed"] {
            let mut bad = original.clone(); bad["lifetime"].as_object_mut().unwrap().remove(key); assert!(parsed(bad).is_err());
        }
        for key in ["projectCodeExecuted","projectFilesRead","repositoryObserved","sdkInspected","credentialsRead","storeContacted"] {
            let mut bad = original.clone(); bad["assurance"][key] = json!(true); assert!(parsed(bad).is_err());
        }
        let mut bad = original.clone(); bad["commandsAttempted"] = json!(2); assert!(parsed(bad).is_err());
        let mut bad = original.clone(); bad["checks"].as_array_mut().unwrap().swap(1,2); assert!(parsed(bad).is_err());
        let mut bad = original.clone(); bad["checks"][0].as_object_mut().unwrap().remove("returnCode"); assert!(parsed(bad).is_err());
        let mut bad = original; bad["checks"][1]["baseline"].as_object_mut().unwrap().remove("build"); assert!(parsed(bad).is_err());
    }
    #[test]
    fn selection_detail_is_optional_closed_and_only_for_the_original_mac_negative_row() {
        let context = Context { platform: Platform::Android, ..context() };
        let parsed = |value: Value, host| decode(&frame("terminal",1,value), &"a".repeat(32), &"b".repeat(32), &context, host);
        let mut original = terminal(&context);
        original["hostPlatform"] = json!("macos");
        original["commandsAttempted"] = json!(1); original["lifetime"]["commands"] = json!(1);
        let rows = original["checks"].as_array_mut().unwrap();
        for row in rows.iter_mut() {
            row["state"] = json!("not-run"); row["reason"] = json!("unselected-installation");
            for key in ["version", "build", "returnCode"] { row[key] = Value::Null; }
            row["assessment"] = json!("not-assessed");
        }
        rows.insert(0, json!({"id":"developer-selection","state":"completed","reason":"selection-unrecognized",
            "version":null,"build":null,"returnCode":0,"baseline":{"kind":"no-local-policy","version":null,"build":null},
            "assessment":"not-assessed","help":"Fixed negative selection guidance"}));
        assert!(parsed(original.clone(), Host::Macos).is_ok());
        // Explicit null is absence on ANY otherwise-valid row, and serializes
        // as absent; it does not require a negative macOS selector observation.
        for (mut value, host) in [(original.clone(), Host::Macos), (terminal(&context), Host::Linux)] {
            for row in value["checks"].as_array_mut().unwrap() { row["selectionDiagnostic"] = Value::Null; }
            match parsed(value, host).unwrap() {
                Frame::Terminal(t) => assert!(serde_json::to_value(t).unwrap()["checks"].as_array().unwrap()
                    .iter().all(|row| row.get("selectionDiagnostic").is_none())),
                _ => panic!("expected terminal"),
            }
        }
        let detail = json!({"stage":"contents","reason":"directory-group-write"});
        let mut detailed = original.clone(); detailed["checks"][0]["selectionDiagnostic"] = detail.clone();
        match parsed(detailed.clone(), Host::Macos).unwrap() {
            Frame::Terminal(t) => assert_eq!(serde_json::to_value(t).unwrap()["checks"][0]["selectionDiagnostic"], detail),
            _ => panic!("expected terminal"),
        }
        for invalid in [json!({"stage":"selector-output","reason":"directory-owner"}), json!({"stage":"alias","reason":"app-name"}),
            json!({"stage":"contents","reason":"unknown"}), json!({"stage":"/PRIVATE","reason":"directory-kind"}),
            json!({"stage":"contents","reason":"directory-kind","path":"PRIVATE"}), json!({"stage":"contents"}), json!([]), json!(false)] {
            let mut bad = detailed.clone(); bad["checks"][0]["selectionDiagnostic"] = invalid; assert!(parsed(bad, Host::Macos).is_err());
        }
        for key in ["id", "state", "reason", "version", "build", "returnCode", "baseline", "assessment", "help"] {
            let mut bad = detailed.clone(); bad["checks"][0].as_object_mut().unwrap().remove(key);
            assert!(parsed(bad, Host::Macos).is_err(), "required original row key {key}");
        }
        let mut bad = detailed.clone(); bad["checks"][0]["extra"] = json!("PRIVATE"); assert!(parsed(bad, Host::Macos).is_err());
        let mut bad = detailed.clone(); bad["checks"][0]["reason"] = json!("observed"); assert!(parsed(bad, Host::Macos).is_err());
        let mut bad = detailed.clone(); bad["checks"][0]["reason"] = json!("nonzero-exit"); bad["checks"][0]["returnCode"] = json!(1);
        assert!(parsed(bad, Host::Macos).is_err());
        let mut bad = original; bad["checks"][1]["selectionDiagnostic"] = detail.clone(); assert!(parsed(bad, Host::Macos).is_err());
        let mut bad = terminal(&context); bad["checks"][0]["selectionDiagnostic"] = detail; assert!(parsed(bad, Host::Linux).is_err());
    }
    #[test]
    fn opaque_incomplete_owner_cannot_become_a_negative_completed_tool_check() {
        let context = Context { platform: Platform::Android, ..context() }; let mut value = terminal(&context);
        value["checks"][1]["state"] = json!("attempted"); value["checks"][1]["reason"] = json!("command-incomplete");
        for key in ["version","build","returnCode"] { value["checks"][1][key] = Value::Null; }
        value["checks"][1]["assessment"] = json!("not-assessed");
        value["checks"][2]["state"] = json!("not-run"); value["checks"][2]["reason"] = json!("stopped");
        for key in ["version","build","returnCode"] { value["checks"][2][key] = Value::Null; }
        value["checks"][2]["assessment"] = json!("not-assessed");
        value["commandsAttempted"] = json!(2); value["lifetime"]["commands"] = json!(2);
        value["lifetime"]["fatal"] = json!(true); value["lifetime"]["complete"] = json!(false); value["outcome"] = json!("partial");
        let parsed = |value: Value| decode(&frame("terminal",1,value), &"a".repeat(32), &"b".repeat(32), &context, Host::Linux);
        match parsed(value.clone()).unwrap() { Frame::Terminal(t) => assert!(!t.lifetime.settled()), _ => panic!("expected terminal") }
        let mut bad = value.clone(); bad["outcome"] = json!("complete"); assert!(parsed(bad).is_err());
        let mut bad = value.clone(); bad["lifetime"]["fatal"] = json!(false); assert!(parsed(bad).is_err());
        let mut bad = value.clone(); bad["checks"][1]["returnCode"] = json!(1); assert!(parsed(bad).is_err());
        let mut bad = value.clone(); bad["outcome"] = json!("timed-out"); assert!(parsed(bad).is_err());
        for (key, data) in [("commands",json!(0)), ("commandDispatched",json!(false)), ("commandDispatched",Value::Null)] {
            let mut bad = value.clone(); bad["lifetime"][key] = data; assert!(parsed(bad).is_err(), "{key}");
        }
        for stop in ["cancelled", "timed-out"] {
            let mut stopped = value.clone(); stopped["checks"][1]["reason"] = json!(stop);
            assert!(parsed(stopped.clone()).is_err()); // No corresponding original STOP observation.
            stopped["outcome"] = json!(stop); stopped["lifetime"]["stopObserved"] = json!(stop);
            assert!(parsed(stopped.clone()).is_ok());
            stopped["lifetime"]["stopObserved"] = json!(if stop == "cancelled" { "timed-out" } else { "cancelled" });
            assert!(parsed(stopped).is_err());
            let mut late = value.clone(); late["outcome"] = json!(stop); late["lifetime"]["stopObserved"] = json!(stop);
            assert!(parsed(late).is_ok()); // Historical command-incomplete is not relabelled by a later STOP.
        }
    }
    #[test]
    fn version_grammars_do_not_turn_arbitrary_tool_output_into_ui_data() {
        for (role, good, bad) in [(CheckId::Git,"2.43.0","2 private"), (CheckId::Java,"21.0.1+12-LTS","21/private"),
            (CheckId::Javac,"1.8.0_431","21.1.2.3.4"), (CheckId::Xcode,"26.3","26.3-private")] {
            assert!(role_version(role,good)); assert!(!role_version(role,bad));
        }
        assert!(!build("17C529 private")); assert!(!build("17C529\n")); assert!(!role_version(CheckId::Xcode,"26.3\n"));
    }
}
