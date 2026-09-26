//! Closed saved unsigned-iOS-archive DATA. Neither paths nor a core terminal
//! grant file, execution, signing, cleanup or original-native finality custody.
use std::path::Path;
use serde::{de, Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError, protocol::valid_id};
// Same pure codec/size/version convention as Python. No Android operation,
// runtime, tool binding, frame, result or ownership type crosses this boundary.
pub(crate) use crate::android_build_protocol::{Content, SavedVersion, RootIdentity};
use crate::android_build_protocol::{native_path, structure};

pub(crate) const PROTOCOL: &str = "mrk-ios-archive/1";
pub(crate) const CONSENT: &str = "saved-ios-unsigned-archive-v1";
pub(crate) const EVENT: &str = "ios-archive-state-changed";
pub(crate) const SCOPE: &str = "local-unsigned-ios-archive-observation";
pub(crate) const TOOLCHAIN_PROFILE: &str = "ios-full-xcode-macos-arm64-v1";
pub(crate) const IPC_LIMIT: usize = 8 * 1024;
pub(crate) const REQUEST_LIMIT: usize = 32 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024;
pub(crate) const STATUS_LIMIT: usize = 64 * 1024;
pub(crate) const MAX_FRAMES: usize = 9;
pub(crate) const LIMITATIONS: [&str; 11] = ["saved-inputs-not-atomic", "project-build-code-is-trusted", "not-network-isolated",
    "unsigned-archive-not-an-ipa", "signing-and-profile-not-validated", "ipa-correspondence-not-validated",
    "source-provenance-not-authenticated", "store-operation-not-requested", "release-readiness-not-assessed",
    "retained-location-not-current-file-authority", "core-terminal-requires-original-native-finality"];

pub(crate) fn invalid() -> BridgeError { BridgeError::new("ios_archive_invalid", "The saved iOS-archive request is invalid.") }
fn protocol_error() -> BridgeError { BridgeError::new("ios_archive_protocol", "The original iOS-archive response did not satisfy its fixed contract.") }
fn keys(value: &Value, expected: &[&str]) -> bool { value.as_object().is_some_and(|o|
    o.len() == expected.len() && expected.iter().all(|k| o.contains_key(*k))) }
fn strict_data(bytes: &[u8], limit: usize, framed: bool) -> Result<Value, BridgeError> {
    crate::android_build_protocol::strict_data(bytes, limit, framed).map_err(|_| protocol_error())
}
pub(crate) fn raw_request(bytes: &[u8]) -> Result<Value, BridgeError> { strict_data(bytes, IPC_LIMIT, false).map_err(|_| invalid()) }
fn nullable<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where D: de::Deserializer<'de>, T: Deserialize<'de> { Option::<T>::deserialize(decoder) }

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform { Ios }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Operation { #[serde(rename = "ios-unsigned-archive")] IOSUnsignedArchive }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: SavedVersion,
    pub(crate) platform: Platform, pub(crate) operation: Operation,
}
impl Context { fn valid(&self) -> bool { valid_id(&self.project_id) && self.draft_revision < u32::MAX
    && self.baseline_generation < u32::MAX && self.saved_config.valid(512 * 1024) && self.saved_version.valid() } }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepare {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: SavedVersion,
}
impl Prepare { pub(crate) fn context(&self) -> Context { Context { project_id: self.project_id.clone(),
    draft_revision: self.draft_revision, baseline_generation: self.baseline_generation, saved_config: self.saved_config.clone(),
    saved_version: self.saved_version.clone(), platform: Platform::Ios, operation: Operation::IOSUnsignedArchive } } }
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start { pub(crate) operation_id: String, pub(crate) owner_generation: String, consent_version: String }
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) owner_generation: String }
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    if !structure(value) { return Err(invalid()); }
    let input = Prepare::deserialize(value).map_err(|_| invalid())?;
    if !input.context().valid() { return Err(invalid()); }
    bounded(value, IPC_LIMIT).map_err(|_| invalid())?; Ok(input)
}
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) || input.consent_version != CONSENT { return Err(invalid()); }
    Ok(input)
}
pub(crate) fn cancel(value: &Value) -> Result<Cancel, BridgeError> {
    let input = Cancel::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) { return Err(invalid()); } Ok(input)
}
pub(crate) fn status_request(value: &Value) -> Result<(), BridgeError> { if keys(value, &[]) { Ok(()) } else { Err(invalid()) } }

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) enum Profile { #[serde(rename = "macos-arm64")] MacArm64 }
impl Profile { pub(crate) fn current() -> Option<Self> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) { Some(Self::MacArm64) } else { None }
} }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToolIdentity {
    pub(crate) device: String, pub(crate) inode: String, pub(crate) mode: u32, pub(crate) uid: u32, pub(crate) gid: u32,
    pub(crate) links: u32, pub(crate) size: u64, pub(crate) mtime_ns: String, pub(crate) ctime_ns: String,
}
impl ToolIdentity { fn valid(&self) -> bool {
    fn decimal(value: &str) -> bool { !value.is_empty() && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|b| b.is_ascii_digit()) && value.parse::<u64>().is_ok() }
    [&self.device, &self.inode, &self.mtime_ns, &self.ctime_ns].into_iter().all(|v| decimal(v)) && self.inode != "0"
        && self.mode & 0o170000 == 0o100000 && self.mode & 0o111 != 0 && self.links == 1 && (1..=64*1024*1024).contains(&self.size)
} }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToolchainBinding {
    schema_version: u32, profile: String, developer_dir: String, developer_identity: RootIdentity,
    xcodebuild_identity: ToolIdentity, sdk: String, sdk_identity: RootIdentity,
}
impl ToolchainBinding {
    /// Native produces comparison DATA from retained originals. This performs
    /// no IO, discovery or tool admission and is not a renderer constructor.
    pub(crate) fn new_data(developer: &Path, developer_identity: RootIdentity, xcodebuild_identity: ToolIdentity,
        sdk: &Path, sdk_identity: RootIdentity) -> Result<Self, BridgeError> {
        let value = Self { schema_version: 1, profile: TOOLCHAIN_PROFILE.into(),
            developer_dir: native_path(developer).ok_or_else(invalid)?.into(), developer_identity,
            xcodebuild_identity, sdk: native_path(sdk).ok_or_else(invalid)?.into(), sdk_identity };
        if !value.valid() { return Err(invalid()); } Ok(value)
    }
    fn valid(&self) -> bool {
        let prefix = format!("{}/Platforms/iPhoneOS.platform/Developer/SDKs/", self.developer_dir);
        self.schema_version == 1 && self.profile == TOOLCHAIN_PROFILE && self.developer_identity.valid()
            && self.xcodebuild_identity.valid() && self.sdk_identity.valid()
            && native_path(Path::new(&self.developer_dir)).is_some() && native_path(Path::new(&self.sdk)).is_some()
            && self.developer_dir.starts_with("/Applications/") && self.developer_dir.ends_with(".app/Contents/Developer")
            && self.sdk.strip_prefix(&prefix).is_some_and(|s| !s.contains('/') && s.ends_with(".sdk"))
    }
}
pub(crate) fn request(operation: &str, generation: &str, context: &Context, profile: Profile,
    project: &RegisteredRoot, cwd: &Path, toolchain: &ToolchainBinding) -> Result<Vec<u8>, BridgeError> {
    if !token(operation) || !token(generation) || !context.valid() || !toolchain.valid() { return Err(invalid()); }
    let observed = project.identity.posix().map_err(|_| invalid())?.preflight_identity();
    let identity = RootIdentity { device: observed.device, inode: observed.inode, mode: observed.mode, uid: observed.uid, gid: observed.gid };
    if !identity.valid() { return Err(invalid()); }
    let data = json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,"rootIdentity":identity,
            "cwd":native_path(cwd).ok_or_else(invalid)?,"toolchain":toolchain}});
    if !structure(&data) { return Err(invalid()); }
    let mut bytes = bounded(&data, REQUEST_LIMIT - 1).map_err(|_| invalid())?; bytes.push(b'\n'); Ok(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome { Complete, Refused, Failed, Cancelled, TimedOut, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable, IntentExpired, StaleIntent,
    SavedConfigMissing, SavedConfigInvalid, SavedConfigChanged, SavedConfigSensitive, SavedConfigUnsafe, SavedConfigTooLarge,
    SavedVersionMissing, SavedVersionInvalid, SavedVersionChanged, SavedVersionSensitive, SavedVersionUnsafe, SavedVersionTooLarge,
    PlatformDisabled, ContainerRequired, SchemeRequired, ContainerMissing, ToolchainUnavailable, ToolchainMismatch,
    ProjectAdmissionRefused, CommandFailed, CommandIncomplete, ArtifactMissing, ArtifactUnsafe, ArtifactChanged,
    ArchiveValidationFailed, InputLimit, ResultLimit, WorkRetained, CleanupUnknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage { Accepted, InputsBound, CheckingXcode, Preparing, Archiving, Inspecting, DisposingSnapshot, DisposingWork }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CommandOutcome { NotDispatched, Exited, Unknown, NotConfigured }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CommandData { pub(crate) outcome: CommandOutcome, #[serde(deserialize_with = "nullable")] pub(crate) exit_code: Option<i32> }
impl CommandData { fn valid(&self) -> bool { (self.outcome == CommandOutcome::Exited) == self.exit_code.is_some() }
    fn zero(&self) -> bool { self.outcome == CommandOutcome::Exited && self.exit_code == Some(0) } }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct Commands { pub(crate) xcode_version: CommandData, pub(crate) ios_sdk: CommandData,
    pub(crate) prepare: CommandData, pub(crate) archive: CommandData }
impl Commands { fn all(&self) -> [&CommandData; 4] { [&self.xcode_version, &self.ios_sdk, &self.prepare, &self.archive] }
    fn valid(&self) -> bool { self.all().into_iter().all(CommandData::valid)
        && [&self.xcode_version, &self.ios_sdk, &self.archive].into_iter().all(|c| c.outcome != CommandOutcome::NotConfigured) } }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ContainerKind { Project, Workspace }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SymbolsPolicy { Disabled, Retain, Required }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection { pub(crate) container_kind: ContainerKind, pub(crate) container: String, pub(crate) scheme: String,
    pub(crate) configuration: String, pub(crate) bundle_id: String, pub(crate) symbols_policy: SymbolsPolicy, pub(crate) preparation_configured: bool }
impl Selection { fn valid(&self) -> bool { [&self.container, &self.scheme, &self.configuration, &self.bundle_id].into_iter().all(|s|
    !s.is_empty() && s.len() <= 512 && !s.chars().any(|c| c < '\u{20}' || c == '\u{7f}')) } }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CoreStatus { Pass, Fail, Missing, Blocked, Invalid, Skip, Manual, Configured, NotApplicable }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CheckId { ArchiveIdentity, ArchiveDsym, ArchiveStructure, OtherCoreFinding }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Finding { pub(crate) check: CheckId, pub(crate) status: CoreStatus }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Activity { pub(crate) stage: Stage, #[serde(deserialize_with = "nullable")] pub(crate) selection: Option<Selection>,
    pub(crate) commands: Commands, pub(crate) findings: Vec<Finding> }
impl Activity {
    fn valid(&self) -> bool { self.commands.valid() && self.findings.len() <= 16
        && self.selection.as_ref().is_none_or(Selection::valid) && (self.stage == Stage::Accepted || self.selection.is_some())
        && (self.findings.is_empty() && self.stage < Stage::Inspecting || self.commands.archive.zero()) }
    fn complete(&self) -> bool {
        let Some(selection) = &self.selection else { return false; };
        self.valid() && self.stage == Stage::DisposingWork && self.commands.xcode_version.zero() && self.commands.ios_sdk.zero()
            && self.commands.archive.zero() && (if selection.preparation_configured { self.commands.prepare.zero() }
                else { self.commands.prepare.outcome == CommandOutcome::NotConfigured && self.commands.prepare.exit_code.is_none() })
            && self.findings.len() == 2 && self.findings[0] == Finding { check: CheckId::ArchiveIdentity, status: CoreStatus::Pass }
            && self.findings[1].check == CheckId::ArchiveDsym && (self.findings[1].status == CoreStatus::Pass
                || selection.symbols_policy == SymbolsPolicy::Disabled && self.findings[1].status == CoreStatus::NotApplicable)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SnapshotDisposition { NotCreated, Removed, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WorkDisposition { NotCreated, Removed, RetainedWork, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OutputDisposition { NotCreated, RetainedIncomplete, RetainedLocalResult, Unknown }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Disposition { pub(crate) snapshot: SnapshotDisposition, pub(crate) work: WorkDisposition, pub(crate) output: OutputDisposition,
    #[serde(deserialize_with = "nullable")] pub(crate) relative_directory: Option<String> }
impl Disposition {
    fn valid(&self, operation: &str) -> bool { if self.output == OutputDisposition::NotCreated { self.relative_directory.is_none() }
        else { self.relative_directory.as_deref() == Some(format!(".mobile-release/desktop-ios-archive/{operation}").as_str()) } }
    fn known(&self) -> bool { self.snapshot != SnapshotDisposition::Unknown && self.work != WorkDisposition::Unknown && self.output != OutputDisposition::Unknown }
    fn complete(&self) -> bool { self.snapshot == SnapshotDisposition::Removed && self.work == WorkDisposition::Removed
        && self.output == OutputDisposition::RetainedLocalResult }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultData { schema_version: u32, scope: String, pub(crate) used_config: Content, pub(crate) used_version: SavedVersion,
    pub(crate) archive: String, pub(crate) entries: u32, pub(crate) bytes: u64, pub(crate) limitations: Vec<String> }
impl ResultData { fn valid(&self, context: &Context, operation: &str) -> bool {
    self.schema_version == 1 && self.scope == SCOPE && self.used_config == context.saved_config && self.used_version == context.saved_version
        && self.archive == format!(".mobile-release/desktop-ios-archive/{operation}/archive.xcarchive")
        && (1..=100_000).contains(&self.entries) && (1..=8 * 1024u64.pow(3)).contains(&self.bytes) && self.limitations == LIMITATIONS
} }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CoreStop { None, Cancelled, TimedOut }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Lifetime {
    pub(crate) complete: bool, pub(crate) fatal: bool, pub(crate) contained: bool,
    #[serde(deserialize_with = "nullable")] pub(crate) command_dispatched: Option<bool>,
    pub(crate) commands: u32, pub(crate) profile_calls: u32, pub(crate) stop_observed: CoreStop,
    pub(crate) input_closed: bool, pub(crate) handlers_restored: bool, pub(crate) invocation_closed: bool,
    pub(crate) snapshot_closed: bool, pub(crate) files_closed: bool, pub(crate) namespace_closed: bool,
}
impl Lifetime { fn valid(&self) -> bool { self.commands <= 4 && self.profile_calls == 0 }
    pub(crate) fn settled(&self) -> bool { self.valid() && self.complete && !self.fatal && self.contained && self.command_dispatched.is_some()
        && self.input_closed && self.handlers_restored && self.invocation_closed && self.snapshot_closed && self.files_closed && self.namespace_closed } }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Terminal { schema_version: u32, context: Context, pub(crate) outcome: Outcome, pub(crate) reason: Reason,
    pub(crate) activity: Activity, pub(crate) disposition: Disposition, #[serde(deserialize_with = "nullable")] pub(crate) result: Option<ResultData>,
    pub(crate) lifetime: Lifetime }
impl Terminal {
    pub(crate) fn settled(&self) -> bool { self.lifetime.settled() && self.disposition.known() }
    fn valid(&self, context: &Context, operation: &str) -> bool {
        if self.schema_version != 1 || &self.context != context || !context.valid() || !self.activity.valid()
            || !self.lifetime.valid() || !self.disposition.valid(operation) { return false; }
        let life = &self.lifetime; let commands = self.activity.commands.all();
        if commands.iter().filter(|c| c.outcome == CommandOutcome::Exited).count() > life.commands as usize { return false; }
        match life.command_dispatched {
            Some(false) if life.commands > 1 || commands.iter().any(|c| !matches!(c.outcome, CommandOutcome::NotDispatched | CommandOutcome::NotConfigured)) => return false,
            Some(true) if life.commands == 0 => return false, _ => {},
        }
        if self.outcome == Outcome::Complete {
            return self.settled() && self.reason == Reason::None && life.stop_observed == CoreStop::None && self.activity.complete()
                && self.disposition.complete() && life.commands == if self.activity.selection.as_ref().is_some_and(|s| s.preparation_configured) { 4 } else { 3 }
                && self.result.as_ref().is_some_and(|r| r.valid(context, operation));
        }
        if self.result.is_some() || self.reason == Reason::None || self.disposition.output == OutputDisposition::RetainedLocalResult
            || (self.outcome == Outcome::Unknown) != (self.reason == Reason::CleanupUnknown)
            || (self.outcome != Outcome::Unknown) != self.settled() { return false; }
        match self.outcome {
            Outcome::Cancelled => self.reason == Reason::Cancelled && life.stop_observed == CoreStop::Cancelled,
            Outcome::TimedOut => self.reason == Reason::TimedOut && life.stop_observed == CoreStop::TimedOut,
            Outcome::Refused => life.command_dispatched == Some(false), _ => true,
        }
    }
}
pub(crate) fn terminal(value: &Value, context: &Context, operation: &str) -> Result<Terminal, BridgeError> {
    if !structure(value) { return Err(protocol_error()); }
    let result = Terminal::deserialize(value).map_err(|_| protocol_error())?;
    if !token(operation) || !result.valid(context, operation) { return Err(protocol_error()); }
    bounded(value, RESPONSE_LIMIT).map_err(|_| protocol_error())?; Ok(result)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Accepted { schema_version: u32, context: Context }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Progress { schema_version: u32, stage: Stage }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope { protocol: String, operation_id: String, owner_generation: String, sequence: u32, kind: String, payload: Value }
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Frame { Accepted, Progress(Stage), Terminal(Terminal) }
pub(crate) struct FrameDecoder { operation: String, generation: String, context: Context, frames: usize, bytes: usize,
    stage: Stage, terminal: bool, failed: bool }
impl FrameDecoder {
    pub(crate) fn new(operation: &str, generation: &str, context: &Context) -> Result<Self, BridgeError> {
        if !token(operation) || !token(generation) || !context.valid() { return Err(protocol_error()); }
        Ok(Self { operation: operation.into(), generation: generation.into(), context: context.clone(), frames: 0, bytes: 0,
            stage: Stage::Accepted, terminal: false, failed: false })
    }
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<Frame, BridgeError> {
        let result = self.push_one(bytes); if result.is_err() { self.failed = true; } result
    }
    fn push_one(&mut self, bytes: &[u8]) -> Result<Frame, BridgeError> {
        if self.failed || self.terminal || self.frames >= MAX_FRAMES { return Err(protocol_error()); }
        self.bytes = self.bytes.checked_add(bytes.len()).ok_or_else(protocol_error)?;
        if self.bytes > RESPONSE_LIMIT { return Err(protocol_error()); }
        let value = strict_data(bytes, RESPONSE_LIMIT, true)?;
        let envelope = Envelope::deserialize(&value).map_err(|_| protocol_error())?;
        if envelope.protocol != PROTOCOL || envelope.operation_id != self.operation || envelope.owner_generation != self.generation
            || envelope.sequence as usize != self.frames { return Err(protocol_error()); }
        let frame = match envelope.kind.as_str() {
            "accepted" if self.frames == 0 => {
                let accepted = Accepted::deserialize(&envelope.payload).map_err(|_| protocol_error())?;
                if accepted.schema_version != 1 || accepted.context != self.context { return Err(protocol_error()); } Frame::Accepted
            },
            "progress" if self.frames > 0 => {
                let progress = Progress::deserialize(&envelope.payload).map_err(|_| protocol_error())?;
                if progress.schema_version != 1 || progress.stage <= self.stage { return Err(protocol_error()); }
                Frame::Progress(progress.stage)
            },
            "terminal" if self.frames > 0 => {
                let t = terminal(&envelope.payload, &self.context, &self.operation)?;
                if t.activity.stage < self.stage { return Err(protocol_error()); } Frame::Terminal(t)
            }, _ => return Err(protocol_error()),
        };
        self.frames += 1;
        match &frame { Frame::Progress(stage) => self.stage = *stage, Frame::Terminal(_) => self.terminal = true, Frame::Accepted => {} }
        Ok(frame)
    }
    pub(crate) fn finish(&mut self) -> Result<(), BridgeError> { if self.settled() { Ok(()) } else { self.failed = true; Err(protocol_error()) } }
    pub(crate) fn settled(&self) -> bool { !self.failed && self.terminal && (2..=MAX_FRAMES).contains(&self.frames) }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { AwaitingConsent, Starting, Running, Stopping, Terminal, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Availability { Available, Busy, Shutdown, CleanupUnknown, DocumentLost, UnsupportedPlatform, RuntimeUnqualified, ToolchainUnqualified }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Projection {
    pub(crate) operation_id: String, pub(crate) owner_generation: String, pub(crate) context: Context,
    pub(crate) phase: Phase, pub(crate) intent_usable: bool, #[serde(deserialize_with = "nullable")] pub(crate) outcome: Option<Outcome>, pub(crate) reason: Reason,
    #[serde(deserialize_with = "nullable")] pub(crate) stage: Option<Stage>, #[serde(deserialize_with = "nullable")] pub(crate) activity: Option<Activity>,
    #[serde(deserialize_with = "nullable")] pub(crate) disposition: Option<Disposition>, #[serde(deserialize_with = "nullable")] pub(crate) result: Option<ResultData>,
}
impl Projection { fn valid(&self) -> bool {
    if !token(&self.operation_id) || !token(&self.owner_generation) || !self.context.valid() { return false; }
    let empty = self.activity.is_none() && self.disposition.is_none() && self.result.is_none();
    match self.phase {
        Phase::AwaitingConsent => self.outcome.is_none() && self.reason == Reason::None && self.stage.is_none() && empty,
        Phase::Starting | Phase::Running | Phase::Stopping => !self.intent_usable && self.outcome.is_none() && empty
            && (self.phase != Phase::Starting || self.stage.is_none()),
        Phase::Unknown => !self.intent_usable && self.outcome == Some(Outcome::Unknown) && self.reason == Reason::CleanupUnknown && empty,
        Phase::Terminal => {
            let Some(outcome) = self.outcome else { return false; };
            if self.intent_usable || outcome == Outcome::Unknown || self.reason == Reason::CleanupUnknown
                || (self.reason == Reason::None) != (outcome == Outcome::Complete) { return false; }
            if outcome == Outcome::Complete { return self.stage == Some(Stage::DisposingWork)
                && self.activity.as_ref().is_some_and(Activity::complete)
                && self.disposition.as_ref().is_some_and(|d| d.complete() && d.valid(&self.operation_id))
                && self.result.as_ref().is_some_and(|r| r.valid(&self.context, &self.operation_id)); }
            if self.result.is_some() || outcome == Outcome::Cancelled && !matches!(self.reason,
                    Reason::Cancelled | Reason::ContextChanged | Reason::DocumentLost | Reason::Shutdown)
                || outcome == Outcome::TimedOut && self.reason != Reason::TimedOut { return false; }
            match (&self.activity, &self.disposition) {
                (Some(a), Some(d)) => a.valid() && self.stage == Some(a.stage) && d.known() && d.valid(&self.operation_id)
                    && d.output != OutputDisposition::RetainedLocalResult,
                (None, None) => true, _ => false,
            }
        },
    }
} }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status { pub(crate) schema_version: u32, pub(crate) status_revision: u32, pub(crate) availability: Availability,
    #[serde(deserialize_with = "nullable")] pub(crate) operation: Option<Projection> }
pub(crate) fn status(value: &Value) -> Result<Status, BridgeError> {
    if !structure(value) { return Err(protocol_error()); }
    let result = Status::deserialize(value).map_err(|_| protocol_error())?;
    if result.schema_version != 1 || result.status_revision == u32::MAX || result.operation.as_ref().is_some_and(|p| !p.valid()) { return Err(protocol_error()); }
    bounded(value, STATUS_LIMIT).map_err(|_| protocol_error())?; Ok(result)
}
pub(crate) fn status_bytes(value: &Status) -> Result<Vec<u8>, BridgeError> {
    let bytes = bounded(value, STATUS_LIMIT).map_err(|_| protocol_error())?;
    status(&strict_data(&bytes, STATUS_LIMIT, false)?)?; Ok(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    // Inert closed DATA only. No Xcode, runtime, descriptor, project, process
    // or qualification permit is acquired by these protocol regressions.
    use super::*;
    pub(crate) fn context() -> Context {
        prepare(&json!({"projectId":"inert-ios","draftRevision":2,"baselineGeneration":3,
            "savedConfig":{"bytes":512,"sha256":"c".repeat(64)},
            "savedVersion":{"source":"release/version.properties","bytes":41,"sha256":"d".repeat(64),"name":"1.2.3","build":7}})).unwrap().context()
    }
    pub(crate) fn complete() -> Value {
        let context = context();
        json!({"schemaVersion":1,"context":context,"outcome":"complete","reason":"none",
            "activity":{"stage":"disposing-work","selection":{"containerKind":"project","container":"ios/Inert.xcodeproj",
                "scheme":"Inert","configuration":"Release","bundleId":"org.example.inert","symbolsPolicy":"retain","preparationConfigured":false},
                "commands":{"xcode-version":{"outcome":"exited","exitCode":0},"ios-sdk":{"outcome":"exited","exitCode":0},
                    "prepare":{"outcome":"not-configured","exitCode":null},"archive":{"outcome":"exited","exitCode":0}},
                "findings":[{"check":"archive-identity","status":"PASS"},{"check":"archive-dsym","status":"PASS"}]},
            "disposition":{"snapshot":"removed","work":"removed","output":"retained-local-result",
                "relativeDirectory":format!(".mobile-release/desktop-ios-archive/{}","a".repeat(32))},
            "result":{"schemaVersion":1,"scope":SCOPE,"usedConfig":context.saved_config,"usedVersion":context.saved_version,
                "archive":format!(".mobile-release/desktop-ios-archive/{}/archive.xcarchive","a".repeat(32)),"entries":10,"bytes":1000,"limitations":LIMITATIONS},
            "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":3,"profileCalls":0,"stopObserved":"none",
                "inputClosed":true,"handlersRestored":true,"invocationClosed":true,"snapshotClosed":true,"filesClosed":true,"namespaceClosed":true}})
    }
    fn check(value: &Value) -> Result<Terminal, BridgeError> { terminal(value, &context(), &"a".repeat(32)) }
    fn envelope(sequence: u32, kind: &str, payload: Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),
            "sequence":sequence,"kind":kind,"payload":payload})).unwrap(); bytes.push(b'\n'); bytes
    }
    #[test]
    fn raw_request_and_consent_cannot_select_tools_or_cross_domains() {
        assert!(raw_request(br#"{"projectId":"one","projectId":"two"}"#).is_err());
        assert!(raw_request(br#"{"x":1.0}"#).is_err());
        let mut data = serde_json::to_value(context()).unwrap();
        data.as_object_mut().unwrap().remove("platform"); data.as_object_mut().unwrap().remove("operation");
        assert!(prepare(&data).is_ok()); data["argv"] = json!(["unopened"]); assert!(prepare(&data).is_err());
        for consent in [CONSENT, crate::android_build_protocol::CONSENT, crate::offline_preflight_protocol::CONSENT] {
            assert_eq!(start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":consent})).is_ok(), consent == CONSENT);
        }
    }
    #[test]
    fn complete_needs_exact_unused_prepare_and_every_original_close() {
        let original = complete(); assert!(check(&original).is_ok());
        for field in ["inputClosed","handlersRestored","invocationClosed","snapshotClosed","filesClosed","namespaceClosed"] {
            let mut value = original.clone(); value["lifetime"][field] = json!(false); assert!(check(&value).is_err(), "{field}");
        }
        for (outcome, code) in [("unknown", Value::Null),("not-dispatched", Value::Null),("exited", json!(0))] {
            let mut value = original.clone(); value["activity"]["commands"]["prepare"] = json!({"outcome":outcome,"exitCode":code});
            assert!(check(&value).is_err(), "{outcome}");
        }
        let mut value = original.clone(); value["activity"]["selection"]["preparationConfigured"] = json!(true);
        value["activity"]["commands"]["prepare"] = json!({"outcome":"exited","exitCode":0}); value["lifetime"]["commands"] = json!(4);
        assert!(check(&value).is_ok());
    }
    #[test]
    fn settled_no_target_one_call_is_not_unknown_or_a_second_call() {
        let mut value = complete(); value["outcome"] = json!("refused"); value["reason"] = json!("command-incomplete"); value["result"] = Value::Null;
        value["activity"]["stage"] = json!("accepted"); value["activity"]["selection"] = Value::Null; value["activity"]["findings"] = json!([]);
        for role in ["xcode-version","ios-sdk","prepare","archive"] { value["activity"]["commands"][role] = json!({"outcome":"not-dispatched","exitCode":null}); }
        value["disposition"] = json!({"snapshot":"not-created","work":"not-created","output":"not-created","relativeDirectory":null});
        value["lifetime"]["commandDispatched"] = json!(false);
        for count in [0, 1] { value["lifetime"]["commands"] = json!(count); assert!(check(&value).is_ok()); }
        value["lifetime"]["commands"] = json!(2); assert!(check(&value).is_err());
        value["lifetime"]["commands"] = json!(1); value["activity"]["commands"]["xcode-version"]["outcome"] = json!("unknown");
        assert!(check(&value).is_err());
    }
    #[test]
    fn frame_domain_order_and_nine_frame_limit_are_fixed() {
        let mut decoder = FrameDecoder::new(&"a".repeat(32), &"b".repeat(32), &context()).unwrap();
        let accepted = envelope(0,"accepted",json!({"schemaVersion":1,"context":context()}));
        assert!(decoder.push(&accepted).is_ok());
        for (index, stage) in ["inputs-bound","checking-xcode","preparing","archiving","inspecting","disposing-snapshot","disposing-work"].iter().enumerate() {
            assert!(decoder.push(&envelope(index as u32+1,"progress",json!({"schemaVersion":1,"stage":stage}))).is_ok());
        }
        assert!(decoder.push(&envelope(8,"terminal",complete())).is_ok()); assert!(decoder.finish().is_ok());
        assert!(decoder.push(&accepted).is_err()); assert!(decoder.finish().is_err());
        let mut foreign = FrameDecoder::new(&"a".repeat(32), &"b".repeat(32), &context()).unwrap();
        let bytes = String::from_utf8(accepted).unwrap().replace(PROTOCOL, crate::android_build_protocol::PROTOCOL).into_bytes();
        assert!(foreign.push(&bytes).is_err());
    }
    #[test]
    fn native_status_cannot_publish_a_provisional_result_or_foreign_retained_path() {
        let complete = check(&complete()).unwrap();
        let mut projection = Projection { operation_id:"a".repeat(32),owner_generation:"b".repeat(32),context:context(),
            phase:Phase::Terminal,intent_usable:false,outcome:Some(Outcome::Complete),reason:Reason::None,stage:Some(Stage::DisposingWork),
            activity:Some(complete.activity),disposition:Some(complete.disposition),result:complete.result };
        assert!(projection.valid());
        for phase in [Phase::AwaitingConsent,Phase::Starting,Phase::Running,Phase::Stopping,Phase::Unknown] {
            let mut provisional = projection.clone(); provisional.phase = phase; assert!(!provisional.valid());
        }
        projection.result.as_mut().unwrap().archive = "/inert/another.xcarchive".into(); assert!(!projection.valid());
    }
}
