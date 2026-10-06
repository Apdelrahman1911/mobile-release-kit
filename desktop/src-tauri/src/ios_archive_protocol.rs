//! Closed saved unsigned-archive/signed-export DATA. Neither paths nor a core terminal
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
pub(crate) const SIGNED_PROTOCOL: &str = "mrk-ios-archive/2";
pub(crate) const SIGNED_CONSENT: &str = "saved-ios-signed-export-v2";
pub(crate) const RECOVERY_PROTOCOL: &str = "mrk-ios-archive/3";
pub(crate) const RECOVERY_CONSENT: &str = "local-ios-recovery-v1";
pub(crate) const ACCOUNT_CONFIRMATION: &str = "account-signing-is-idle-and-restore-owned-state";
pub(crate) const PROJECT_CONFIRMATION: &str = "project-build-inputs-are-idle-and-restore-owned-state";
pub(crate) const EVENT: &str = "ios-archive-state-changed";
pub(crate) const SCOPE: &str = "local-unsigned-ios-archive-observation";
pub(crate) const SIGNED_SCOPE: &str = "local-signed-ios-artifact-validation";
pub(crate) const TOOLCHAIN_PROFILE: &str = "ios-full-xcode-macos-arm64-v1";
pub(crate) const X64_TOOLCHAIN_PROFILE: &str = "ios-full-xcode-macos-x86_64-v1";
pub(crate) const IPC_LIMIT: usize = 8 * 1024;
pub(crate) const REQUEST_LIMIT: usize = 32 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024;
pub(crate) const STATUS_LIMIT: usize = 64 * 1024;
// Only the outer native Status version; core frames/results keep their own versions.
pub(crate) const STATUS_SCHEMA_VERSION: u32 = 2;
pub(crate) const MAX_FRAMES: usize = 9;
pub(crate) const SIGNED_MAX_FRAMES: usize = 13;
pub(crate) const SIGNED_COMMAND_LIMIT: u32 = 4096;
pub(crate) const SIGNED_PROFILE_LIMIT: u32 = 1024;
pub(crate) const RECOVERY_MAX_FRAMES: usize = 5;
pub(crate) const RECOVERY_COMMAND_LIMIT: u32 = 32;
pub(crate) const RECOVERY_LIMITATIONS: [&str; 4] = ["local-recovery-only", "manual-recovery-not-supported",
    "user-confirmation-is-not-worker-finality", "no-store-operation"];
pub(crate) const LIMITATIONS: [&str; 11] = ["saved-inputs-not-atomic", "project-build-code-is-trusted", "not-network-isolated",
    "unsigned-archive-not-an-ipa", "signing-and-profile-not-validated", "ipa-correspondence-not-validated",
    "source-provenance-not-authenticated", "store-operation-not-requested", "release-readiness-not-assessed",
    "retained-location-not-current-file-authority", "core-terminal-requires-original-native-finality"];
pub(crate) const SIGNED_LIMITATIONS: [&str; 9] = ["saved-inputs-not-atomic", "project-build-code-is-trusted", "not-network-isolated",
    "single-primary-profile", "source-provenance-not-authenticated", "store-operation-not-requested",
    "release-readiness-not-assessed", "retained-location-not-current-file-authority", "core-terminal-requires-original-native-finality"];

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
// A mode-only field may be absent, but an explicit null is never absence.
fn present<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where D: de::Deserializer<'de>, T: Deserialize<'de> { T::deserialize(decoder).map(Some) }

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform { Ios }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Operation {
    #[serde(rename = "ios-unsigned-archive")] IOSUnsignedArchive,
    #[serde(rename = "ios-signed-export")] IOSSignedExport,
    #[serde(rename = "ios-local-recovery")] IOSLocalRecovery,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RecoveryAction { Inspect, Account, Project }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryIntent {
    pub(crate) action: RecoveryAction,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) session: Option<String>,
}
impl RecoveryIntent { fn valid(&self) -> bool { match self.action {
    RecoveryAction::Inspect => self.session.is_none(),
    RecoveryAction::Account | RecoveryAction::Project => self.session.as_deref().is_some_and(token),
} } }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SigningAssignment {
    pub(crate) kind: String, pub(crate) record_id: String,
    pub(crate) record_revision: u32, pub(crate) context_revision: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SigningPolicy {
    pub(crate) team_id: String, pub(crate) distribution_certificate_sha256: String,
    pub(crate) assignments: Vec<SigningAssignment>,
}
impl SigningPolicy {
    fn valid(&self) -> bool {
        let kinds: Vec<&str> = self.assignments.iter().map(|row| row.kind.as_str()).collect();
        self.team_id.len() == 10 && self.team_id.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            && self.distribution_certificate_sha256.len() == 64
            && self.distribution_certificate_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && matches!(kinds.as_slice(), ["apple-p12", "apple-profile"]
                | ["apple-p12", "apple-profile", "ios-firebase"]
                | ["apple-p12", "apple-profile", "project-read-token"]
                | ["apple-p12", "apple-profile", "ios-firebase", "project-read-token"])
            && self.assignments.iter().enumerate().all(|(index, row)| token(&row.record_id)
                && (1..u32::MAX).contains(&row.record_revision) && (1..u32::MAX).contains(&row.context_revision)
                && row.context_revision == self.assignments[0].context_revision
                && self.assignments[..index].iter().all(|prior| prior.record_id != row.record_id))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) draft_revision: Option<u32>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) baseline_generation: Option<u32>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) saved_config: Option<Content>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) saved_version: Option<SavedVersion>,
    pub(crate) platform: Platform, pub(crate) operation: Operation,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) signing: Option<SigningPolicy>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) recovery: Option<RecoveryIntent>,
}
impl Context { fn valid(&self) -> bool {
        if !valid_id(&self.project_id) { return false; }
        if self.recovery() { return self.draft_revision.is_none() && self.baseline_generation.is_none()
            && self.saved_config.is_none() && self.saved_version.is_none() && self.signing.is_none()
            && self.recovery.as_ref().is_some_and(RecoveryIntent::valid); }
        self.recovery.is_none() && self.draft_revision.is_some_and(|v| v < u32::MAX)
            && self.baseline_generation.is_some_and(|v| v < u32::MAX)
            && self.saved_config.as_ref().is_some_and(|v| v.valid(512 * 1024))
            && self.saved_version.as_ref().is_some_and(SavedVersion::valid)
            && self.signed() == self.signing.is_some() && self.signing.as_ref().is_none_or(SigningPolicy::valid)
    }
    pub(crate) fn signed(&self) -> bool { self.operation == Operation::IOSSignedExport }
    pub(crate) fn recovery(&self) -> bool { self.operation == Operation::IOSLocalRecovery }
    pub(crate) fn account_lifecycle(&self) -> bool { self.signed() || self.recovery() }
    pub(crate) fn frame_limit(&self) -> usize { if self.recovery() { RECOVERY_MAX_FRAMES } else if self.signed() { SIGNED_MAX_FRAMES } else { MAX_FRAMES } }
    fn protocol(&self) -> &'static str { if self.recovery() { RECOVERY_PROTOCOL } else if self.signed() { SIGNED_PROTOCOL } else { PROTOCOL } }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepare {
    pub(crate) project_id: String,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) draft_revision: Option<u32>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) baseline_generation: Option<u32>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) saved_config: Option<Content>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) saved_version: Option<SavedVersion>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) signing: Option<SigningPolicy>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) recovery: Option<RecoveryIntent>,
}
impl Prepare { pub(crate) fn context(&self) -> Context { Context { project_id: self.project_id.clone(),
    draft_revision: self.draft_revision, baseline_generation: self.baseline_generation, saved_config: self.saved_config.clone(),
    saved_version: self.saved_version.clone(), platform: Platform::Ios,
    operation: if self.recovery.is_some() { Operation::IOSLocalRecovery } else if self.signing.is_some() { Operation::IOSSignedExport } else { Operation::IOSUnsignedArchive },
    signing: self.signing.clone(), recovery: self.recovery.clone() } } }
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start { pub(crate) operation_id: String, pub(crate) owner_generation: String, consent_version: String,
    #[serde(default, deserialize_with = "present")]
    confirmation: Option<String>,
}
impl Start { pub(crate) fn consent_matches(&self, context: &Context) -> bool {
    if !context.valid() { return false; }
    if let Some(recovery) = &context.recovery { return self.consent_version == RECOVERY_CONSENT && self.confirmation.as_deref() == match recovery.action {
        RecoveryAction::Inspect => None, RecoveryAction::Account => Some(ACCOUNT_CONFIRMATION), RecoveryAction::Project => Some(PROJECT_CONFIRMATION),
    }; }
    self.confirmation.is_none() && self.consent_version == (if context.signed() { SIGNED_CONSENT } else { CONSENT })
} }
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
    if !token(&input.operation_id) || !token(&input.owner_generation)
        || ![CONSENT, SIGNED_CONSENT, RECOVERY_CONSENT].contains(&input.consent_version.as_str())
        || input.confirmation.as_deref().is_some_and(|confirmation| input.consent_version != RECOVERY_CONSENT
            || ![ACCOUNT_CONFIRMATION, PROJECT_CONFIRMATION].contains(&confirmation)) { return Err(invalid()); }
    Ok(input)
}
pub(crate) fn cancel(value: &Value) -> Result<Cancel, BridgeError> {
    let input = Cancel::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) { return Err(invalid()); } Ok(input)
}
pub(crate) fn status_request(value: &Value) -> Result<(), BridgeError> { if keys(value, &[]) { Ok(()) } else { Err(invalid()) } }

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) enum Profile {
    #[serde(rename = "macos-arm64")] MacArm64,
    #[serde(rename = "macos-x86_64")] MacX64,
}
impl Profile {
    pub(crate) fn current() -> Option<Self> {
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) { Some(Self::MacArm64) }
        else if cfg!(all(target_os = "macos", target_arch = "x86_64", target_pointer_width = "64")) { Some(Self::MacX64) }
        else { None }
    }
    fn toolchain_profile(self) -> &'static str { match self {
        Self::MacArm64 => TOOLCHAIN_PROFILE,
        Self::MacX64 => X64_TOOLCHAIN_PROFILE,
    } }
}
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
pub(crate) struct SigningToolBindings { security: ToolIdentity, codesign: ToolIdentity, openssl: ToolIdentity }
impl SigningToolBindings {
    /// Comparison DATA from the original native tool owner, never renderer IO.
    pub(crate) fn new_data(security: ToolIdentity, codesign: ToolIdentity, openssl: ToolIdentity) -> Result<Self, BridgeError> {
        let value = Self { security, codesign, openssl };
        if !value.valid() { return Err(invalid()); } Ok(value)
    }
    fn valid(&self) -> bool { [&self.security, &self.codesign, &self.openssl].into_iter().all(|tool|
        tool.valid() && tool.uid == 0 && tool.mode & 0o022 == 0) }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToolchainBinding {
    schema_version: u32, profile: String, developer_dir: String, developer_identity: RootIdentity,
    xcodebuild_identity: ToolIdentity, sdk: String, sdk_identity: RootIdentity,
}
impl ToolchainBinding {
    /// Native produces comparison DATA from retained originals. This performs
    /// no IO, discovery or tool admission and is not a renderer constructor.
    pub(crate) fn new_data(profile: Profile, developer: &Path, developer_identity: RootIdentity, xcodebuild_identity: ToolIdentity,
        sdk: &Path, sdk_identity: RootIdentity) -> Result<Self, BridgeError> {
        let value = Self { schema_version: 1, profile: profile.toolchain_profile().into(),
            developer_dir: native_path(developer).ok_or_else(invalid)?.into(), developer_identity,
            xcodebuild_identity, sdk: native_path(sdk).ok_or_else(invalid)?.into(), sdk_identity };
        if !value.valid() { return Err(invalid()); } Ok(value)
    }
    fn valid(&self) -> bool {
        let prefix = format!("{}/Platforms/iPhoneOS.platform/Developer/SDKs/", self.developer_dir);
        self.schema_version == 1 && matches!(self.profile.as_str(), TOOLCHAIN_PROFILE | X64_TOOLCHAIN_PROFILE)
            && self.developer_identity.valid()
            && self.xcodebuild_identity.valid() && self.sdk_identity.valid()
            && native_path(Path::new(&self.developer_dir)).is_some() && native_path(Path::new(&self.sdk)).is_some()
            && self.developer_dir.starts_with("/Applications/") && self.developer_dir.ends_with(".app/Contents/Developer")
            && self.sdk.strip_prefix(&prefix).is_some_and(|s| !s.contains('/') && s.ends_with(".sdk"))
    }
    fn matches_profile(&self, profile: Profile) -> bool {
        self.valid() && self.profile == profile.toolchain_profile()
    }
}
pub(crate) fn request(operation: &str, generation: &str, context: &Context, profile: Profile,
    project: &RegisteredRoot, cwd: &Path, toolchain: &ToolchainBinding) -> Result<Vec<u8>, BridgeError> {
    if context.account_lifecycle() { return Err(invalid()); }
    request_data(operation, generation, context, profile, project, cwd, toolchain, None)
}
pub(crate) fn request_signed(operation: &str, generation: &str, context: &Context, profile: Profile,
    project: &RegisteredRoot, cwd: &Path, toolchain: &ToolchainBinding, signing_tools: &SigningToolBindings,
    signing_context: &Content) -> Result<Vec<u8>, BridgeError> {
    if !context.signed() { return Err(invalid()); }
    request_data(operation, generation, context, profile, project, cwd, toolchain, Some((signing_tools, signing_context)))
}
fn request_data(operation: &str, generation: &str, context: &Context, profile: Profile,
    project: &RegisteredRoot, cwd: &Path, toolchain: &ToolchainBinding,
    signing: Option<(&SigningToolBindings, &Content)>) -> Result<Vec<u8>, BridgeError> {
    if !token(operation) || !token(generation) || !context.valid() || context.recovery() || !toolchain.matches_profile(profile)
        || context.signed() != signing.is_some()
        || signing.is_some_and(|(tools, comparison)| !tools.valid() || !comparison.valid(512 * 1024)) { return Err(invalid()); }
    let observed = project.identity.posix().map_err(|_| invalid())?.preflight_identity();
    let identity = RootIdentity { device: observed.device, inode: observed.inode, mode: observed.mode, uid: observed.uid, gid: observed.gid };
    if !identity.valid() { return Err(invalid()); }
    let mut data = json!({"protocol":context.protocol(),"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,"rootIdentity":identity,
            "cwd":native_path(cwd).ok_or_else(invalid)?,"toolchain":toolchain}});
    if let Some((tools, comparison)) = signing {
        data["native"]["signingTools"] = json!(tools);
        data["native"]["signingContext"] = json!(comparison);
    }
    if !structure(&data) { return Err(invalid()); }
    let mut bytes = bounded(&data, REQUEST_LIMIT - 1).map_err(|_| invalid())?; bytes.push(b'\n'); Ok(bytes)
}
pub(crate) fn request_recovery(operation: &str, generation: &str, context: &Context, profile: Profile,
    project: &RegisteredRoot, cwd: &Path, security: &ToolIdentity) -> Result<Vec<u8>, BridgeError> {
    if !token(operation) || !token(generation) || !context.valid() || !context.recovery()
        || !security.valid() || security.uid != 0 || security.mode & 0o022 != 0 { return Err(invalid()); }
    let observed = project.identity.posix().map_err(|_| invalid())?.preflight_identity();
    let identity = RootIdentity { device: observed.device, inode: observed.inode, mode: observed.mode, uid: observed.uid, gid: observed.gid };
    if !identity.valid() { return Err(invalid()); }
    let data = json!({"protocol":RECOVERY_PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,"rootIdentity":identity,
            "cwd":native_path(cwd).ok_or_else(invalid)?,"security":security}});
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
    SigningPolicyRequired, SigningInputMissing, SigningInputInvalid, SigningValidationFailed,
    AccountAdmissionRefused, ArtifactValidationFailed, SymbolsUploadNotRequested, RecoveryAttention,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage { Accepted, InputsBound, CheckingXcode, ValidatingSigning, MaterializingSigning,
    Preparing, Archiving, Exporting, RestoringSigning, Inspecting, RecoveringAccount, RecoveringProject, DisposingSnapshot, DisposingWork }
impl Stage { fn valid(self, context: &Context) -> bool {
    if context.recovery() { return matches!(self, Self::Accepted | Self::RecoveringAccount | Self::RecoveringProject | Self::DisposingWork); }
    !matches!(self, Self::RecoveringAccount | Self::RecoveringProject) && (context.signed() || !matches!(self,
        Self::ValidatingSigning | Self::MaterializingSigning | Self::Exporting | Self::RestoringSigning))
} }
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
    pub(crate) prepare: CommandData, pub(crate) archive: CommandData,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) export: Option<CommandData>,
}
impl Commands { fn all(&self) -> Vec<&CommandData> {
        let mut commands = vec![&self.xcode_version, &self.ios_sdk, &self.prepare, &self.archive];
        commands.extend(self.export.iter()); commands
    }
    fn valid(&self, signed: bool) -> bool { self.export.is_some() == signed && self.all().into_iter().all(CommandData::valid)
        && [&self.xcode_version, &self.ios_sdk, &self.archive].into_iter().all(|c| c.outcome != CommandOutcome::NotConfigured)
        && self.export.as_ref().is_none_or(|c| c.outcome != CommandOutcome::NotConfigured) }
}
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
pub(crate) enum CheckId { ArchiveIdentity, ArchiveDsym, ArchiveStructure, OtherCoreFinding, SigningMaterial, ProfileMaterial,
    FirebaseMaterial, ArtifactCorrespondence, IpaStructure, IpaProfile, IpaEntitlements, IpaSigner, IpaValidation, SymbolsUpload }
impl CheckId { fn valid(self, signed: bool) -> bool { signed || matches!(self,
    Self::ArchiveIdentity | Self::ArchiveDsym | Self::ArchiveStructure | Self::OtherCoreFinding) } }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Finding { pub(crate) check: CheckId, pub(crate) status: CoreStatus }
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ArchiveActivity { pub(crate) selection: Option<Selection>, pub(crate) commands: Commands,
    pub(crate) findings: Vec<Finding> }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(from = "ActivityWire", into = "ActivityWire")]
pub(crate) struct Activity { pub(crate) stage: Stage, build: Option<ArchiveActivity> }
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum ActivityWire { Archive(ArchiveActivityWire), Recovery(RecoveryActivityWire) }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveActivityWire { stage: Stage, #[serde(deserialize_with = "nullable")] selection: Option<Selection>,
    commands: Commands, findings: Vec<Finding> }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryActivityWire { stage: Stage }
impl From<ActivityWire> for Activity { fn from(value: ActivityWire) -> Self { match value {
    ActivityWire::Archive(value) => Self { stage: value.stage, build: Some(ArchiveActivity {
        selection: value.selection, commands: value.commands, findings: value.findings }) },
    ActivityWire::Recovery(value) => Self { stage: value.stage, build: None },
} } }
impl From<Activity> for ActivityWire { fn from(value: Activity) -> Self { match value.build {
    Some(build) => Self::Archive(ArchiveActivityWire { stage: value.stage, selection: build.selection,
        commands: build.commands, findings: build.findings }),
    None => Self::Recovery(RecoveryActivityWire { stage: value.stage }),
} } }
impl Activity {
    /// Borrow typed archive DATA; the caller must still require its exact mode.
    /// Recovery has no archive activity, and this does not grant execution.
    pub(crate) fn archive_activity(&self) -> Option<&ArchiveActivity> { self.build.as_ref() }
    fn valid(&self, context: &Context) -> bool {
        if !self.stage.valid(context) { return false; }
        if context.recovery() { return self.build.is_none(); }
        let Some(build) = &self.build else { return false; };
        let signed = context.signed();
        build.commands.valid(signed) && build.findings.len() <= 16
            && build.findings.iter().all(|row| row.check.valid(signed))
            && build.selection.as_ref().is_none_or(Selection::valid) && (self.stage == Stage::Accepted || build.selection.is_some())
            && ((signed || build.findings.is_empty()) && self.stage < Stage::Inspecting
                || build.commands.archive.zero() && (!signed || build.commands.export.as_ref().is_some_and(CommandData::zero)))
    }
    fn complete(&self, context: &Context) -> bool {
        if !self.valid(context) || self.stage != Stage::DisposingWork { return false; }
        if context.recovery() { return true; }
        let Some(build) = &self.build else { return false; };
        let Some(selection) = &build.selection else { return false; };
        if !build.commands.xcode_version.zero() || !build.commands.ios_sdk.zero()
            || !build.commands.archive.zero() || !(if selection.preparation_configured { build.commands.prepare.zero() }
                else { build.commands.prepare.outcome == CommandOutcome::NotConfigured && build.commands.prepare.exit_code.is_none() }) { return false; }
        if let Some(signing) = &context.signing {
            let mut expected = vec![CheckId::SigningMaterial, CheckId::ProfileMaterial, CheckId::ArtifactCorrespondence,
                CheckId::IpaStructure, CheckId::IpaProfile, CheckId::IpaEntitlements, CheckId::IpaSigner];
            if signing.assignments.iter().any(|row| row.kind == "ios-firebase") { expected.push(CheckId::FirebaseMaterial); }
            return selection.symbols_policy != SymbolsPolicy::Required && build.commands.export.as_ref().is_some_and(CommandData::zero)
                && build.findings.len() == expected.len() && expected.iter().all(|check|
                    build.findings.iter().any(|row| row.check == *check && row.status == CoreStatus::Pass));
        }
        build.findings.len() == 2 && build.findings[0] == Finding { check: CheckId::ArchiveIdentity, status: CoreStatus::Pass }
            && build.findings[1].check == CheckId::ArchiveDsym && (build.findings[1].status == CoreStatus::Pass
                || selection.symbols_policy == SymbolsPolicy::Disabled && build.findings[1].status == CoreStatus::NotApplicable)
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
pub(crate) struct Pairing { pub(crate) native_paths: u32, pub(crate) native_identities: u32, pub(crate) present_symbol_slices: u32 }
impl Pairing { fn valid(&self) -> bool { (1..=100_000).contains(&self.native_paths)
    && (1..=100_000).contains(&self.native_identities) && self.present_symbol_slices <= 100_000 } }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultData { schema_version: u32, scope: String, pub(crate) used_config: Content, pub(crate) used_version: SavedVersion,
    pub(crate) archive: String, pub(crate) entries: u32, pub(crate) bytes: u64, pub(crate) limitations: Vec<String>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) ipa: Option<String>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) ipa_bytes: Option<u64>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) pairing: Option<Pairing>,
}
impl ResultData { fn valid(&self, context: &Context, operation: &str) -> bool {
    !context.recovery() && self.schema_version == 1 && self.scope == (if context.signed() { SIGNED_SCOPE } else { SCOPE })
        && context.saved_config.as_ref() == Some(&self.used_config) && context.saved_version.as_ref() == Some(&self.used_version)
        && self.archive == format!(".mobile-release/desktop-ios-archive/{operation}/archive.xcarchive")
        && (1..=100_000).contains(&self.entries) && (1..=8 * 1024u64.pow(3)).contains(&self.bytes)
        && if context.signed() {
            self.limitations == SIGNED_LIMITATIONS && self.ipa.as_deref().is_some_and(|path|
                path.strip_prefix(&format!(".mobile-release/desktop-ios-archive/{operation}/export/")).is_some_and(|name|
                    !name.is_empty() && name.len() <= 255 && name.ends_with(".ipa")
                    && !name.chars().any(|c| c < '\u{20}' || c == '\u{7f}' || matches!(c, '/' | '\\' | ':'))))
                && self.ipa_bytes.is_some_and(|bytes| (1..=4 * 1024u64.pow(3)).contains(&bytes))
                && self.pairing.as_ref().is_some_and(Pairing::valid)
        } else { self.limitations == LIMITATIONS && self.ipa.is_none() && self.ipa_bytes.is_none() && self.pairing.is_none() }
} }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RecoveryState { Idle, Pending, Busy, Conflict, ManualRequired, Recovered, RecoveredWithConflict, Absent, CleanupOnly, NotInspected }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RecoveryNext { None, Wait, Ordinary, Manual, Preserve }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryRow { pub(crate) status: RecoveryState, #[serde(deserialize_with = "nullable")]
    pub(crate) session: Option<String>, pub(crate) next: RecoveryNext }
impl RecoveryRow { fn valid(&self, account: bool) -> bool {
    use RecoveryState as R; use RecoveryNext as N;
    if self.session.as_deref().is_some_and(|value| !token(value)) || account && matches!(self.status, R::CleanupOnly | R::NotInspected)
        || !account && self.status == R::RecoveredWithConflict { return false; }
    if matches!(self.status, R::Pending | R::CleanupOnly | R::ManualRequired | R::Recovered | R::RecoveredWithConflict | R::Absent)
        && self.session.is_none() || matches!(self.status, R::Idle | R::NotInspected) && self.session.is_some() { return false; }
    match self.status {
        R::Idle | R::Recovered | R::Absent => self.next == N::None,
        R::Busy => self.next == N::Wait,
        R::ManualRequired => self.next == N::Manual,
        R::Pending => matches!(self.next, N::Ordinary | N::Manual),
        R::CleanupOnly => self.next == N::Ordinary,
        R::Conflict | R::RecoveredWithConflict | R::NotInspected => self.next == N::Preserve,
    }
} }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecoveryReport { schema_version: u32, scope: String,
    #[serde(deserialize_with = "nullable")] pub(crate) account: Option<RecoveryRow>,
    #[serde(deserialize_with = "nullable")] pub(crate) project: Option<RecoveryRow>,
    pub(crate) limitations: Vec<String>,
}
impl RecoveryReport { fn valid(&self, context: &Context) -> bool {
    let Some(intent) = &context.recovery else { return false; };
    if !context.recovery() || self.schema_version != 1 || self.scope != "local-ios-recovery" || self.limitations != RECOVERY_LIMITATIONS { return false; }
    for (action, row) in [(RecoveryAction::Account, &self.account), (RecoveryAction::Project, &self.project)] {
        let needed = intent.action == RecoveryAction::Inspect || intent.action == action;
        if needed != row.is_some() { return false; }
        if let Some(row) = row {
            if !row.valid(action == RecoveryAction::Account) { return false; }
            if intent.action == RecoveryAction::Inspect {
                if matches!(row.status, RecoveryState::Recovered | RecoveryState::RecoveredWithConflict | RecoveryState::Absent) { return false; }
            } else if row.session != intent.session || !matches!(row.status, RecoveryState::Recovered | RecoveryState::RecoveredWithConflict
                | RecoveryState::Absent | RecoveryState::Busy | RecoveryState::Conflict | RecoveryState::ManualRequired) { return false; }
        }
    }
    true
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
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) signing_closed: Option<bool>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) build_inputs_closed: Option<bool>,
    #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
    pub(crate) material_retired: Option<bool>,
}
impl Lifetime { fn valid(&self, context: &Context) -> bool {
        self.commands <= (if context.recovery() { RECOVERY_COMMAND_LIMIT } else if context.signed() { SIGNED_COMMAND_LIMIT } else { 4 })
            && self.profile_calls <= (if context.signed() { SIGNED_PROFILE_LIMIT } else { 0 })
            && [self.signing_closed, self.build_inputs_closed, self.material_retired].iter().all(|flag| flag.is_some() == context.account_lifecycle())
    }
    pub(crate) fn settled(&self) -> bool {
        let account = self.signing_closed.is_some();
        self.commands <= (if account { SIGNED_COMMAND_LIMIT } else { 4 }) && self.profile_calls <= (if account { SIGNED_PROFILE_LIMIT } else { 0 })
        && self.complete && !self.fatal && self.contained && self.command_dispatched.is_some()
        && self.input_closed && self.handlers_restored && self.invocation_closed && self.snapshot_closed && self.files_closed && self.namespace_closed
        && [self.signing_closed, self.build_inputs_closed, self.material_retired].iter().all(|flag| if account { *flag == Some(true) } else { flag.is_none() }) }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(try_from = "TerminalWire")]
pub(crate) struct Terminal { schema_version: u32, pub(crate) context: Context, pub(crate) outcome: Outcome, pub(crate) reason: Reason,
    pub(crate) activity: Activity, pub(crate) disposition: Option<Disposition>, pub(crate) result: Option<ResultData>,
    pub(crate) report: Option<RecoveryReport>, pub(crate) lifetime: Lifetime }
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum TerminalWire { Archive(ArchiveTerminalWire), Recovery(RecoveryTerminalWire) }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArchiveTerminalWire { schema_version: u32, context: Context, outcome: Outcome, reason: Reason,
    activity: Activity, disposition: Disposition, #[serde(deserialize_with = "nullable")] result: Option<ResultData>, lifetime: Lifetime }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryTerminalWire { schema_version: u32, context: Context, outcome: Outcome, reason: Reason,
    activity: Activity, #[serde(deserialize_with = "nullable")] report: Option<RecoveryReport>, lifetime: Lifetime }
impl TryFrom<TerminalWire> for Terminal { type Error = &'static str;
    fn try_from(value: TerminalWire) -> Result<Self, Self::Error> { match value {
        TerminalWire::Archive(v) if !v.context.recovery() => Ok(Self { schema_version: v.schema_version, context: v.context,
            outcome: v.outcome, reason: v.reason, activity: v.activity, disposition: Some(v.disposition), result: v.result, report: None, lifetime: v.lifetime }),
        TerminalWire::Recovery(v) if v.context.recovery() => Ok(Self { schema_version: v.schema_version, context: v.context,
            outcome: v.outcome, reason: v.reason, activity: v.activity, disposition: None, result: None, report: v.report, lifetime: v.lifetime }),
        _ => Err("wrong iOS terminal mode"),
    } }
}
impl Serialize for Terminal { fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;
    if self.context.recovery() {
        if self.disposition.is_some() || self.result.is_some() { return Err(S::Error::custom("wrong recovery terminal fields")); }
        RecoveryTerminalWire { schema_version: self.schema_version, context: self.context.clone(), outcome: self.outcome, reason: self.reason,
            activity: self.activity.clone(), report: self.report.clone(), lifetime: self.lifetime.clone() }.serialize(serializer)
    } else {
        if self.report.is_some() { return Err(S::Error::custom("wrong archive terminal fields")); }
        ArchiveTerminalWire { schema_version: self.schema_version, context: self.context.clone(), outcome: self.outcome, reason: self.reason,
            activity: self.activity.clone(), disposition: self.disposition.clone().ok_or_else(|| S::Error::custom("missing archive disposition"))?,
            result: self.result.clone(), lifetime: self.lifetime.clone() }.serialize(serializer)
    }
} }
impl Terminal {
    pub(crate) fn settled(&self) -> bool { self.lifetime.valid(&self.context) && self.lifetime.settled()
        && (if self.context.recovery() { self.disposition.is_none() && self.result.is_none() }
            else { self.report.is_none() && self.disposition.as_ref().is_some_and(Disposition::known) }) }
    fn valid(&self, context: &Context, operation: &str) -> bool {
        if self.schema_version != 1 || &self.context != context || !context.valid() || !self.activity.valid(context)
            || !self.lifetime.valid(context) { return false; }
        if context.recovery() {
            if self.disposition.is_some() || self.result.is_some()
                || self.report.as_ref().is_some_and(|report| !self.settled() || !report.valid(context)) { return false; }
        } else if self.report.is_some() || !self.disposition.as_ref().is_some_and(|d| d.valid(operation)) { return false; }
        let life = &self.lifetime;
        let commands = self.activity.build.as_ref().map_or_else(Vec::new, |build| build.commands.all());
        if commands.iter().filter(|c| c.outcome == CommandOutcome::Exited).count() > life.commands as usize { return false; }
        match life.command_dispatched {
            Some(false) if life.commands > 1 || commands.iter().any(|c| !matches!(c.outcome, CommandOutcome::NotDispatched | CommandOutcome::NotConfigured)) => return false,
            Some(true) if life.commands == 0 => return false, _ => {},
        }
        if self.outcome == Outcome::Complete {
            if !self.settled() || self.reason != Reason::None || life.stop_observed != CoreStop::None || !self.activity.complete(context) { return false; }
            if context.recovery() { return self.report.is_some(); }
            let roles = if self.activity.build.as_ref().and_then(|b| b.selection.as_ref()).is_some_and(|s| s.preparation_configured) { 4 } else { 3 };
            return self.disposition.as_ref().is_some_and(Disposition::complete)
                && (if context.signed() { life.commands >= roles + 1 && life.profile_calls >= 3 } else { life.commands == roles })
                && self.result.as_ref().is_some_and(|r| r.valid(context, operation));
        }
        if self.result.is_some() || self.reason == Reason::None || self.disposition.as_ref().is_some_and(|d| d.output == OutputDisposition::RetainedLocalResult)
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
        if self.failed || self.terminal || self.frames >= self.context.frame_limit() { return Err(protocol_error()); }
        self.bytes = self.bytes.checked_add(bytes.len()).ok_or_else(protocol_error)?;
        if self.bytes > RESPONSE_LIMIT { return Err(protocol_error()); }
        let value = strict_data(bytes, RESPONSE_LIMIT, true)?;
        let envelope = Envelope::deserialize(&value).map_err(|_| protocol_error())?;
        if envelope.protocol != self.context.protocol() || envelope.operation_id != self.operation || envelope.owner_generation != self.generation
            || envelope.sequence as usize != self.frames { return Err(protocol_error()); }
        let frame = match envelope.kind.as_str() {
            "accepted" if self.frames == 0 => {
                let accepted = Accepted::deserialize(&envelope.payload).map_err(|_| protocol_error())?;
                if accepted.schema_version != 1 || accepted.context != self.context { return Err(protocol_error()); } Frame::Accepted
            },
            "progress" if self.frames > 0 => {
                let progress = Progress::deserialize(&envelope.payload).map_err(|_| protocol_error())?;
                if progress.schema_version != 1 || !progress.stage.valid(&self.context) || progress.stage <= self.stage { return Err(protocol_error()); }
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
    pub(crate) fn settled(&self) -> bool { !self.failed && self.terminal && (2..=self.context.frame_limit()).contains(&self.frames) }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { AwaitingConsent, Starting, Running, Stopping, Terminal, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Availability { Available, Busy, Shutdown, CleanupUnknown, DocumentLost, UnsupportedPlatform, RuntimeUnqualified, ToolchainUnqualified }
// Mode-gate DATA only. These bits never grant consent, original ownership,
// signing material, exact-session recovery or finality.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ModeCapabilities { pub(crate) unsigned: bool, pub(crate) signed: bool, pub(crate) recovery: bool }
impl ModeCapabilities {
    pub(crate) const NONE: Self = Self { unsigned: false, signed: false, recovery: false };
    pub(crate) fn supports(self, operation: Operation) -> bool { match operation {
        Operation::IOSUnsignedArchive => self.unsigned, Operation::IOSSignedExport => self.signed,
        Operation::IOSLocalRecovery => self.recovery,
    } }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(try_from = "ProjectionWire")]
pub(crate) struct Projection {
    pub(crate) operation_id: String, pub(crate) owner_generation: String, pub(crate) context: Context,
    pub(crate) phase: Phase, pub(crate) intent_usable: bool, pub(crate) outcome: Option<Outcome>, pub(crate) reason: Reason,
    pub(crate) stage: Option<Stage>, pub(crate) activity: Option<Activity>,
    pub(crate) disposition: Option<Disposition>, pub(crate) result: Option<ResultData>, pub(crate) report: Option<RecoveryReport>,
}
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum ProjectionWire { Archive(ArchiveProjectionWire), Recovery(RecoveryProjectionWire) }
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArchiveProjectionWire {
    operation_id: String, owner_generation: String, context: Context, phase: Phase, intent_usable: bool,
    #[serde(deserialize_with = "nullable")] outcome: Option<Outcome>, reason: Reason,
    #[serde(deserialize_with = "nullable")] stage: Option<Stage>, #[serde(deserialize_with = "nullable")] activity: Option<Activity>,
    #[serde(deserialize_with = "nullable")] disposition: Option<Disposition>, #[serde(deserialize_with = "nullable")] result: Option<ResultData>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryProjectionWire {
    operation_id: String, owner_generation: String, context: Context, phase: Phase, intent_usable: bool,
    #[serde(deserialize_with = "nullable")] outcome: Option<Outcome>, reason: Reason,
    #[serde(deserialize_with = "nullable")] stage: Option<Stage>, #[serde(deserialize_with = "nullable")] activity: Option<Activity>,
    #[serde(deserialize_with = "nullable")] report: Option<RecoveryReport>,
}
impl TryFrom<ProjectionWire> for Projection { type Error = &'static str;
    fn try_from(value: ProjectionWire) -> Result<Self, Self::Error> { match value {
        ProjectionWire::Archive(v) if !v.context.recovery() => Ok(Self { operation_id: v.operation_id, owner_generation: v.owner_generation,
            context: v.context, phase: v.phase, intent_usable: v.intent_usable, outcome: v.outcome, reason: v.reason, stage: v.stage,
            activity: v.activity, disposition: v.disposition, result: v.result, report: None }),
        ProjectionWire::Recovery(v) if v.context.recovery() => Ok(Self { operation_id: v.operation_id, owner_generation: v.owner_generation,
            context: v.context, phase: v.phase, intent_usable: v.intent_usable, outcome: v.outcome, reason: v.reason, stage: v.stage,
            activity: v.activity, disposition: None, result: None, report: v.report }),
        _ => Err("wrong iOS status mode"),
    } }
}
impl Serialize for Projection { fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;
    if self.context.recovery() {
        if self.disposition.is_some() || self.result.is_some() { return Err(S::Error::custom("wrong recovery status fields")); }
        RecoveryProjectionWire { operation_id: self.operation_id.clone(), owner_generation: self.owner_generation.clone(), context: self.context.clone(),
            phase: self.phase, intent_usable: self.intent_usable, outcome: self.outcome, reason: self.reason, stage: self.stage,
            activity: self.activity.clone(), report: self.report.clone() }.serialize(serializer)
    } else {
        if self.report.is_some() { return Err(S::Error::custom("wrong archive status fields")); }
        ArchiveProjectionWire { operation_id: self.operation_id.clone(), owner_generation: self.owner_generation.clone(), context: self.context.clone(),
            phase: self.phase, intent_usable: self.intent_usable, outcome: self.outcome, reason: self.reason, stage: self.stage,
            activity: self.activity.clone(), disposition: self.disposition.clone(), result: self.result.clone() }.serialize(serializer)
    }
} }
impl Projection { fn valid(&self) -> bool {
    if !token(&self.operation_id) || !token(&self.owner_generation) || !self.context.valid()
        || self.stage.is_some_and(|stage| !stage.valid(&self.context))
        || self.context.recovery() && (self.disposition.is_some() || self.result.is_some()) || !self.context.recovery() && self.report.is_some() { return false; }
    let empty = self.activity.is_none() && self.disposition.is_none() && self.result.is_none() && self.report.is_none();
    match self.phase {
        Phase::AwaitingConsent => self.outcome.is_none() && self.reason == Reason::None && self.stage.is_none() && empty,
        Phase::Starting | Phase::Running | Phase::Stopping => !self.intent_usable && self.outcome.is_none() && empty
            && (self.phase != Phase::Starting || self.stage.is_none()),
        Phase::Unknown => !self.intent_usable && self.outcome == Some(Outcome::Unknown) && self.reason == Reason::CleanupUnknown && empty,
        Phase::Terminal => {
            let Some(outcome) = self.outcome else { return false; };
            if self.intent_usable || outcome == Outcome::Unknown || self.reason == Reason::CleanupUnknown
                || (self.reason == Reason::None) != (outcome == Outcome::Complete) { return false; }
            if outcome == Outcome::Complete {
                if self.stage != Some(Stage::DisposingWork) || !self.activity.as_ref().is_some_and(|a| a.complete(&self.context)) { return false; }
                return if self.context.recovery() { self.report.as_ref().is_some_and(|r| r.valid(&self.context)) }
                    else { self.disposition.as_ref().is_some_and(|d| d.complete() && d.valid(&self.operation_id))
                        && self.result.as_ref().is_some_and(|r| r.valid(&self.context, &self.operation_id)) };
            }
            if self.result.is_some() || outcome == Outcome::Cancelled && !matches!(self.reason,
                    Reason::Cancelled | Reason::ContextChanged | Reason::DocumentLost | Reason::Shutdown)
                || outcome == Outcome::TimedOut && self.reason != Reason::TimedOut { return false; }
            if self.context.recovery() { return match &self.activity {
                Some(a) => a.valid(&self.context) && self.stage == Some(a.stage) && self.report.as_ref().is_none_or(|r| r.valid(&self.context)),
                None => self.report.is_none(),
            }; }
            match (&self.activity, &self.disposition) {
                (Some(a), Some(d)) => a.valid(&self.context) && self.stage == Some(a.stage) && d.known() && d.valid(&self.operation_id)
                    && d.output != OutputDisposition::RetainedLocalResult,
                (None, None) => true, _ => false,
            }
        },
    }
} }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status { pub(crate) schema_version: u32, pub(crate) status_revision: u32, pub(crate) availability: Availability,
    pub(crate) mode_capabilities: ModeCapabilities,
    #[serde(deserialize_with = "nullable")] pub(crate) operation: Option<Projection> }
pub(crate) fn status(value: &Value) -> Result<Status, BridgeError> {
    if !structure(value) { return Err(protocol_error()); }
    let result = Status::deserialize(value).map_err(|_| protocol_error())?;
    if result.schema_version != STATUS_SCHEMA_VERSION || result.status_revision == u32::MAX || result.operation.as_ref().is_some_and(|p| !p.valid()) { return Err(protocol_error()); }
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
    fn status_requires_exact_native_mode_data_without_changing_core_or_request_versions() {
        let original = json!({"schemaVersion":STATUS_SCHEMA_VERSION,"statusRevision":1,"availability":"available",
            "modeCapabilities":{"unsigned":true,"signed":false,"recovery":false},"operation":null});
        let parsed = status(&original).unwrap();
        assert!(parsed.mode_capabilities.supports(Operation::IOSUnsignedArchive));
        assert!(!parsed.mode_capabilities.supports(Operation::IOSSignedExport));
        assert!(!parsed.mode_capabilities.supports(Operation::IOSLocalRecovery));
        assert_eq!(status(&serde_json::from_slice(&status_bytes(&parsed).unwrap()).unwrap()).unwrap(), parsed);
        for modes in [Value::Null, json!({}), json!([]), json!({"unsigned":true,"signed":false}),
            json!({"unsigned":true,"signed":1,"recovery":false}),
            json!({"unsigned":true,"signed":false,"recovery":false,"all":true})] {
            let mut changed = original.clone(); changed["modeCapabilities"] = modes;
            assert!(status(&changed).is_err());
        }
        let mut missing = original.clone(); missing.as_object_mut().unwrap().remove("modeCapabilities");
        assert!(status(&missing).is_err());
        let mut old = original.clone(); old["schemaVersion"] = json!(1); assert!(status(&old).is_err());
        let mut request = json!({"projectId":"inert-ios","recovery":{"action":"inspect"}});
        request["modeCapabilities"] = original["modeCapabilities"].clone(); assert!(prepare(&request).is_err());
        // Outer Status v2 is not a change to the actual core frame/terminal protocol.
        assert!(check(&complete()).is_ok());
    }
    #[test]
    fn native_status_cannot_publish_a_provisional_result_or_foreign_retained_path() {
        let complete = check(&complete()).unwrap();
        let mut projection = Projection { operation_id:"a".repeat(32),owner_generation:"b".repeat(32),context:context(),
            phase:Phase::Terminal,intent_usable:false,outcome:Some(Outcome::Complete),reason:Reason::None,stage:Some(Stage::DisposingWork),
            activity:Some(complete.activity),disposition:complete.disposition,result:complete.result,report:None };
        assert!(projection.valid());
        for phase in [Phase::AwaitingConsent,Phase::Starting,Phase::Running,Phase::Stopping,Phase::Unknown] {
            let mut provisional = projection.clone(); provisional.phase = phase; assert!(!provisional.valid());
        }
        projection.result.as_mut().unwrap().archive = "/inert/another.xcarchive".into(); assert!(!projection.valid());
    }
    pub(crate) fn signed_context() -> Context {
        let mut value = serde_json::to_value(context()).unwrap();
        value["operation"] = json!("ios-signed-export");
        value["signing"] = json!({"teamId":"A1B2C3D4E5","distributionCertificateSha256":"e".repeat(64),
            "assignments":[{"kind":"apple-p12","recordId":"1".repeat(32),"recordRevision":1,"contextRevision":3},
                {"kind":"apple-profile","recordId":"2".repeat(32),"recordRevision":2,"contextRevision":3}]});
        let selected = Context::deserialize(&value).unwrap(); assert!(selected.valid()); selected
    }
    fn signed_complete() -> Value {
        let selected = signed_context(); let mut value = complete();
        value["context"] = json!(selected);
        value["activity"]["commands"]["export"] = json!({"outcome":"exited","exitCode":0});
        value["activity"]["findings"] = json!(["signing-material","profile-material","artifact-correspondence",
            "ipa-structure","ipa-profile","ipa-entitlements","ipa-signer"].map(|check| json!({"check":check,"status":"PASS"})));
        value["lifetime"]["commands"] = json!(4); value["lifetime"]["profileCalls"] = json!(3);
        for field in ["signingClosed","buildInputsClosed","materialRetired"] { value["lifetime"][field] = json!(true); }
        value["result"]["scope"] = json!(SIGNED_SCOPE); value["result"]["limitations"] = json!(SIGNED_LIMITATIONS);
        value["result"]["ipa"] = json!(format!(".mobile-release/desktop-ios-archive/{}/export/Inert.ipa", "a".repeat(32)));
        value["result"]["ipaBytes"] = json!(512);
        value["result"]["pairing"] = json!({"nativePaths":1,"nativeIdentities":1,"presentSymbolSlices":0});
        value
    }
    fn signed_check(value: &Value) -> Result<Terminal, BridgeError> { terminal(value, &signed_context(), &"a".repeat(32)) }
    #[test]
    fn signed_policy_is_exact_ordered_nonnull_and_consent_cannot_cross_modes() {
        let signed = signed_context(); assert!(signed.signed()); assert_eq!(signed.frame_limit(), 13);
        assert!(!context().signed()); assert_eq!(context().frame_limit(), 9);
        let original = serde_json::to_value(&signed).unwrap();
        for field in ["teamId","distributionCertificateSha256","assignments"] {
            let mut data = original.clone(); data["signing"].as_object_mut().unwrap().remove(field);
            assert!(!Context::deserialize(&data).map(|c| c.valid()).unwrap_or(false));
        }
        for signing in [Value::Null, json!({})] {
            let mut data = original.clone(); data["signing"] = signing;
            assert!(!Context::deserialize(&data).map(|c| c.valid()).unwrap_or(false));
        }
        for fault in ["order","same-record","other-context","zero-revision","max-revision","lower-team","uppercase-hash","unsigned-mode","missing-policy"] {
            let mut data = original.clone();
            match fault {
                "order" => data["signing"]["assignments"].as_array_mut().unwrap().swap(0,1),
                "same-record" => data["signing"]["assignments"][1]["recordId"] = json!("1".repeat(32)),
                "other-context" => data["signing"]["assignments"][1]["contextRevision"] = json!(4),
                "zero-revision" => data["signing"]["assignments"][0]["recordRevision"] = json!(0),
                "max-revision" => data["signing"]["assignments"][0]["recordRevision"] = json!(u32::MAX),
                "lower-team" => data["signing"]["teamId"] = json!("a1B2C3D4E5"),
                "uppercase-hash" => data["signing"]["distributionCertificateSha256"] = json!("E".repeat(64)),
                "unsigned-mode" => data["operation"] = json!("ios-unsigned-archive"),
                _ => { data.as_object_mut().unwrap().remove("signing"); },
            }
            assert!(!Context::deserialize(&data).map(|c| c.valid()).unwrap_or(false), "{fault}");
        }
        let mut review = original.clone(); review.as_object_mut().unwrap().remove("platform"); review.as_object_mut().unwrap().remove("operation");
        assert_eq!(prepare(&review).unwrap().context(), signed);
        // The four-assignment request has 69 key/value nodes, above the old
        // renderer's unsigned scanner ceiling but within this unchanged codec.
        let optional: &[&[&str]] = &[&[], &["ios-firebase"], &["project-read-token"], &["ios-firebase", "project-read-token"]];
        for kinds in optional {
            let mut data = review.clone();
            for (index, kind) in kinds.iter().enumerate() {
                data["signing"]["assignments"].as_array_mut().unwrap().push(json!({"kind":kind,
                    "recordId":if *kind == "ios-firebase" { "3".repeat(32) } else { "4".repeat(32) },
                    "recordRevision":index+3,"contextRevision":3}));
            }
            let raw = serde_json::to_vec(&data).unwrap(); assert!(raw.len() < IPC_LIMIT);
            assert_eq!(prepare(&raw_request(&raw).unwrap()).unwrap().context().signing.unwrap().assignments.len(), kinds.len()+2);
        }
        for field in ["signingTools","signingContext","native","privateMaterial"] {
            let mut data = review.clone(); data[field] = Value::Null; assert!(prepare(&data).is_err(), "{field}");
        }
        for consent in [CONSENT, SIGNED_CONSENT] {
            let input = start(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":consent})).unwrap();
            assert_eq!(input.consent_matches(&signed), consent == SIGNED_CONSENT);
            assert_eq!(input.consent_matches(&context()), consent == CONSENT);
        }
    }
    #[test]
    fn signed_terminal_requires_export_pairing_and_each_original_close_without_widening_unsigned() {
        let original = signed_complete(); assert!(signed_check(&original).is_ok()); assert!(check(&original).is_err());
        for field in ["signingClosed","buildInputsClosed","materialRetired"] {
            for replacement in [Value::Null, json!(false)] {
                let mut value = original.clone(); value["lifetime"][field] = replacement; assert!(signed_check(&value).is_err(), "{field}");
            }
            let mut value = original.clone(); value["lifetime"].as_object_mut().unwrap().remove(field); assert!(signed_check(&value).is_err());
            let mut value = complete(); value["lifetime"][field] = Value::Null; assert!(check(&value).is_err());
        }
        for field in ["ipa","ipaBytes","pairing"] {
            let mut value = original.clone(); value["result"][field] = Value::Null; assert!(signed_check(&value).is_err());
            value["result"].as_object_mut().unwrap().remove(field); assert!(signed_check(&value).is_err());
            let mut unsigned = complete(); unsigned["result"][field] = Value::Null; assert!(check(&unsigned).is_err());
        }
        for fault in ["no-export","null-export","failed-export","old-scope","bad-pair","foreign-ipa","symbols-required","profile-count","command-bound","profile-bound","duplicate-finding"] {
            let mut value = original.clone();
            match fault {
                "no-export" => { value["activity"]["commands"].as_object_mut().unwrap().remove("export"); },
                "null-export" => value["activity"]["commands"]["export"] = Value::Null,
                "failed-export" => value["activity"]["commands"]["export"]["exitCode"] = json!(1),
                "old-scope" => value["result"]["scope"] = json!(SCOPE),
                "bad-pair" => value["result"]["pairing"]["nativeIdentities"] = json!(0),
                "foreign-ipa" => value["result"]["ipa"] = json!("/inert/other.ipa"),
                "symbols-required" => value["activity"]["selection"]["symbolsPolicy"] = json!("required"),
                "profile-count" => value["lifetime"]["profileCalls"] = json!(2),
                "command-bound" => value["lifetime"]["commands"] = json!(SIGNED_COMMAND_LIMIT+1),
                "profile-bound" => value["lifetime"]["profileCalls"] = json!(SIGNED_PROFILE_LIMIT+1),
                _ => value["activity"]["findings"][0] = value["activity"]["findings"][1].clone(),
            }
            assert!(signed_check(&value).is_err(), "{fault}");
        }
        let mut unsigned = complete(); unsigned["activity"]["commands"]["export"] = Value::Null; assert!(check(&unsigned).is_err());
        assert!(check(&complete()).is_ok());
    }
    #[test]
    fn signed_frames_keep_thirteen_original_ordered_frames_and_refuse_unsigned_relabelling() {
        let frame = |sequence, kind, payload| {
            let mut value: Value = serde_json::from_slice(&envelope(sequence, kind, payload)).unwrap();
            value["protocol"] = json!(SIGNED_PROTOCOL); let mut bytes = serde_json::to_vec(&value).unwrap(); bytes.push(b'\n'); bytes
        };
        let mut decoder = FrameDecoder::new(&"a".repeat(32), &"b".repeat(32), &signed_context()).unwrap();
        let accepted = frame(0,"accepted",json!({"schemaVersion":1,"context":signed_context()}));
        assert!(decoder.push(&accepted).is_ok());
        for (index, stage) in ["inputs-bound","checking-xcode","validating-signing","materializing-signing","preparing","archiving",
            "exporting","restoring-signing","inspecting","disposing-snapshot","disposing-work"].iter().enumerate() {
            assert!(decoder.push(&frame(index as u32+1,"progress",json!({"schemaVersion":1,"stage":stage}))).is_ok());
        }
        assert!(decoder.push(&frame(12,"terminal",signed_complete())).is_ok()); assert!(decoder.finish().is_ok());
        assert!(decoder.push(&accepted).is_err()); assert!(decoder.finish().is_err());
        let mut unsigned = FrameDecoder::new(&"a".repeat(32), &"b".repeat(32), &context()).unwrap();
        assert!(unsigned.push(&envelope(0,"accepted",json!({"schemaVersion":1,"context":context()}))).is_ok());
        assert!(unsigned.push(&envelope(1,"progress",json!({"schemaVersion":1,"stage":"validating-signing"}))).is_err());
        let mut wrong = FrameDecoder::new(&"a".repeat(32), &"b".repeat(32), &signed_context()).unwrap();
        assert!(wrong.push(&envelope(0,"accepted",json!({"schemaVersion":1,"context":signed_context()}))).is_err());
    }
    #[test]
    fn native_request_pairs_exact_mac_profile_with_sdk_and_signing_data() {
        let developer = Path::new("/Applications/Xcode_Inert.app/Contents/Developer");
        let sdk = developer.join("Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.0.sdk");
        let directory = RootIdentity { device:"1".into(), inode:"2".into(), mode:0o040755, uid:0, gid:0 };
        let tool = ToolIdentity { device:"1".into(),inode:"3".into(),mode:0o100555,uid:0,gid:0,links:1,size:512,
            mtime_ns:"4".into(),ctime_ns:"5".into() };
        let signing = SigningToolBindings::new_data(tool.clone(), tool.clone(), tool.clone()).unwrap();
        let canonical = Content { bytes:17, sha256:"a".repeat(64) };
        let project = RegisteredRoot { path:"/inert/project".into(),
            identity:crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity()) };
        for (profile, native, toolchain, opposite) in [
            (Profile::MacArm64, "macos-arm64", "ios-full-xcode-macos-arm64-v1", Profile::MacX64),
            (Profile::MacX64, "macos-x86_64", "ios-full-xcode-macos-x86_64-v1", Profile::MacArm64),
        ] {
            let binding = ToolchainBinding::new_data(profile, developer, directory.clone(), tool.clone(), &sdk, directory.clone()).unwrap();
            assert!(binding.matches_profile(profile));
            assert!(!binding.matches_profile(opposite));
            let unsigned = context(); let signed = signed_context();
            for encoded in [
                request(&"a".repeat(32), &"b".repeat(32), &unsigned, profile, &project, &project.path, &binding).unwrap(),
                request_signed(&"a".repeat(32), &"b".repeat(32), &signed, profile,
                    &project, &project.path, &binding, &signing, &canonical).unwrap(),
            ] {
                let value: Value = serde_json::from_slice(&encoded).unwrap();
                assert_eq!(value["native"]["profile"], json!(native));
                assert_eq!(value["native"]["toolchain"]["profile"], json!(toolchain));
            }
            assert!(request(&"a".repeat(32), &"b".repeat(32), &unsigned, opposite, &project, &project.path, &binding).is_err());
            assert!(request_signed(&"a".repeat(32), &"b".repeat(32), &signed, opposite,
                &project, &project.path, &binding, &signing, &canonical).is_err());
            for fault in ["foreign-sdk", "clt", "unknown-profile", "file-not-directory"] {
                let mut changed = binding.clone();
                match fault {
                    "foreign-sdk" => changed.sdk = "/inert/foreign.sdk".into(),
                    "clt" => changed.developer_dir = "/Library/Developer/CommandLineTools".into(),
                    "unknown-profile" => changed.profile = "ios-full-xcode-macos-unknown-v1".into(),
                    _ => changed.sdk_identity.mode = 0o100444,
                }
                assert!(request(&"a".repeat(32), &"b".repeat(32), &unsigned, profile, &project, &project.path, &changed).is_err(), "{fault}");
            }
            let mut foreign_signing = signing.clone(); foreign_signing.security.uid = 501;
            assert!(request_signed(&"a".repeat(32), &"b".repeat(32), &signed, profile,
                &project, &project.path, &binding, &foreign_signing, &canonical).is_err());
        }
    }
    #[test]
    fn signing_tool_data_is_not_ambient_or_renderer_authority() {
        let tool = ToolIdentity { device:"1".into(),inode:"2".into(),mode:0o100555,uid:0,gid:0,links:1,size:512,
            mtime_ns:"3".into(),ctime_ns:"4".into() };
        assert!(SigningToolBindings::new_data(tool.clone(),tool.clone(),tool.clone()).is_ok());
        for fault in ["uid","writable","not-executable","link"] {
            let mut changed = tool.clone();
            match fault { "uid" => changed.uid=1001, "writable" => changed.mode=0o100775,
                "not-executable" => changed.mode=0o100444, _ => changed.links=2 }
            assert!(SigningToolBindings::new_data(changed,tool.clone(),tool.clone()).is_err(), "{fault}");
        }
    }
    pub(crate) fn recovery_context() -> Context {
        prepare(&json!({"projectId":"inert-ios","recovery":{"action":"inspect"}})).unwrap().context()
    }
    fn recovery_complete() -> Value {
        let mut lifetime = signed_complete()["lifetime"].clone();
        lifetime["commands"] = json!(0); lifetime["profileCalls"] = json!(0); lifetime["commandDispatched"] = json!(false);
        json!({"schemaVersion":1,"context":recovery_context(),"outcome":"complete","reason":"none",
            "activity":{"stage":"disposing-work"},"lifetime":lifetime,
            "report":{"schemaVersion":1,"scope":"local-ios-recovery",
                "account":{"status":"pending","session":"c".repeat(32),"next":"ordinary"},
                "project":{"status":"idle","session":null,"next":"none"},"limitations":RECOVERY_LIMITATIONS}})
    }
    #[test]
    fn recovery_prepare_is_closed_without_saved_inputs_and_confirmation_is_action_bound() {
        let context = recovery_context(); assert!(context.recovery() && context.account_lifecycle() && !context.signed());
        assert_eq!(context.frame_limit(), 5);
        for field in ["draftRevision","baselineGeneration","savedConfig","savedVersion","signing","native","security"] {
            let mut value = json!({"projectId":"inert-ios","recovery":{"action":"inspect"}}); value[field] = Value::Null;
            assert!(prepare(&value).is_err(), "{field}");
        }
        for action in ["inspect","account","project"] {
            let intent = if action == "inspect" { json!({"action":action}) } else { json!({"action":action,"session":"c".repeat(32)}) };
            let context = prepare(&json!({"projectId":"inert-ios","recovery":intent})).unwrap().context();
            for confirmation in [None,Some(ACCOUNT_CONFIRMATION),Some(PROJECT_CONFIRMATION)] {
                let mut input = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":RECOVERY_CONSENT});
                if let Some(value) = confirmation { input["confirmation"] = json!(value); }
                let start = start(&input).unwrap();
                assert_eq!(start.consent_matches(&context), confirmation == match action {
                    "account" => Some(ACCOUNT_CONFIRMATION), "project" => Some(PROJECT_CONFIRMATION), _ => None });
                assert!(!start.consent_matches(&signed_context())); assert!(!start.consent_matches(&super::tests::context()));
            }
        }
        for intent in [json!({"action":"inspect","session":"c".repeat(32)}),json!({"action":"account"}),
            json!({"action":"project","session":null}),json!({"action":"manual","session":"c".repeat(32)})] {
            assert!(prepare(&json!({"projectId":"inert-ios","recovery":intent})).is_err());
        }
        let input = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":RECOVERY_CONSENT,"confirmation":null});
        assert!(start(&input).is_err());
    }
    #[test]
    fn recovery_reports_are_exact_session_data_and_never_provisional_artifacts() {
        let context = recovery_context(); let original = recovery_complete();
        let accepted = terminal(&original,&context,&"a".repeat(32)).unwrap();
        assert!(accepted.settled()); assert!(accepted.disposition.is_none() && accepted.result.is_none());
        assert_eq!(serde_json::to_value(&accepted).unwrap(), original);
        for field in ["result","disposition"] {
            let mut value = original.clone(); value[field] = Value::Null; assert!(terminal(&value,&context,&"a".repeat(32)).is_err());
        }
        for field in ["selection","commands","findings"] {
            let mut value = original.clone(); value["activity"][field] = Value::Null;
            assert!(terminal(&value,&context,&"a".repeat(32)).is_err());
        }
        for field in ["inputClosed","handlersRestored","invocationClosed","snapshotClosed","filesClosed","namespaceClosed",
            "signingClosed","buildInputsClosed","materialRetired"] {
            let mut value = original.clone(); value["lifetime"][field] = json!(false);
            assert!(terminal(&value,&context,&"a".repeat(32)).is_err(), "{field}");
        }
        let mut value = original.clone(); value["lifetime"]["commands"] = json!(33); value["lifetime"]["commandDispatched"] = json!(true);
        assert!(terminal(&value,&context,&"a".repeat(32)).is_err());
        let mut value = original.clone(); value["lifetime"]["profileCalls"] = json!(1);
        assert!(terminal(&value,&context,&"a".repeat(32)).is_err());
        let mut value = original.clone(); value["outcome"] = json!("unknown"); value["reason"] = json!("cleanup-unknown"); value["lifetime"]["complete"] = json!(false);
        assert!(terminal(&value,&context,&"a".repeat(32)).is_err()); value["report"] = Value::Null;
        assert!(terminal(&value,&context,&"a".repeat(32)).is_ok());
        let action = prepare(&json!({"projectId":"inert-ios","recovery":{"action":"account","session":"c".repeat(32)}})).unwrap().context();
        let mut value = original.clone(); value["context"] = json!(action); value["report"]["project"] = Value::Null;
        value["report"]["account"] = json!({"status":"recovered","session":"c".repeat(32),"next":"none"});
        assert!(terminal(&value,&action,&"a".repeat(32)).is_ok());
        value["report"]["account"]["session"] = json!("d".repeat(32)); assert!(terminal(&value,&action,&"a".repeat(32)).is_err());
        let projection = Projection { operation_id:"a".repeat(32),owner_generation:"b".repeat(32),context:context.clone(),
            phase:Phase::Terminal,intent_usable:false,outcome:Some(Outcome::Complete),reason:Reason::None,stage:Some(Stage::DisposingWork),
            activity:Some(accepted.activity),disposition:None,result:None,report:accepted.report };
        let status = Status { schema_version:STATUS_SCHEMA_VERSION,status_revision:1,availability:Availability::Available,
            mode_capabilities:ModeCapabilities { unsigned:false,signed:false,recovery:true },operation:Some(projection) };
        let encoded = status_bytes(&status).unwrap(); let data: Value = serde_json::from_slice(&encoded).unwrap();
        assert!(!data["operation"].as_object().unwrap().contains_key("result"));
        assert!(!data["operation"].as_object().unwrap().contains_key("disposition"));
        let mut early = status.clone(); early.operation.as_mut().unwrap().phase = Phase::Running;
        assert!(status_bytes(&early).is_err());
    }
    #[test]
    fn recovery_frames_keep_the_five_frame_domain_and_refuse_archive_work() {
        let context = recovery_context();
        let frame = |sequence, kind, payload| {
            let mut value: Value = serde_json::from_slice(&envelope(sequence,kind,payload)).unwrap();
            value["protocol"] = json!(RECOVERY_PROTOCOL); let mut bytes = serde_json::to_vec(&value).unwrap(); bytes.push(b'\n'); bytes
        };
        let mut decoder = FrameDecoder::new(&"a".repeat(32),&"b".repeat(32),&context).unwrap();
        assert!(decoder.push(&frame(0,"accepted",json!({"schemaVersion":1,"context":context}))).is_ok());
        for (index,stage) in ["recovering-account","recovering-project","disposing-work"].iter().enumerate() {
            assert!(decoder.push(&frame(index as u32+1,"progress",json!({"schemaVersion":1,"stage":stage}))).is_ok());
        }
        assert!(decoder.push(&frame(4,"terminal",recovery_complete())).is_ok()); assert!(decoder.finish().is_ok());
        let mut wrong = FrameDecoder::new(&"a".repeat(32),&"b".repeat(32),&context).unwrap();
        assert!(wrong.push(&frame(0,"accepted",json!({"schemaVersion":1,"context":context}))).is_ok());
        assert!(wrong.push(&frame(1,"progress",json!({"schemaVersion":1,"stage":"archiving"}))).is_err());
    }
}
