//! Closed Android build comparison, transport and redacted projection DATA.
//!
//! Draft against A2 `_desktop_android_build_protocol.py` SHA256
//! a8053b6845677ddf6fb1ea7d3e4af90745c1b169c8f3cbcd03cbd9133459aca6.
//! No owner, launch, file access, tool admission, permit or qualification here.
//! A parsed core terminal and a settled frame decoder NEVER establish native
//! finality: the original runtime/process/pipe/close/join owners must still settle.
use std::{collections::BTreeMap, fmt, path::Path};
use serde::{de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor}, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use crate::{asset_source::RegisteredRoot, edit_protocol::{bounded, token}, error::BridgeError,
    protocol::valid_id};

pub(crate) const PROTOCOL: &str = "mrk-android-build/1";
pub(crate) const CONSENT: &str = "saved-android-build-inspect-v1";
pub(crate) const EVENT: &str = "android-build-state-changed";
pub(crate) const SCOPE: &str = "local-post-build-artifact-observation";
pub(crate) const TOOLCHAIN_PROFILE: &str = "android-local-linux-gnu-x86_64-v1";
pub(crate) const IPC_LIMIT: usize = 8 * 1024;
pub(crate) const REQUEST_LIMIT: usize = 32 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024;
pub(crate) const STATUS_LIMIT: usize = 64 * 1024;
pub(crate) const MAX_FRAMES: usize = 8;
pub(crate) const MAX_FINDINGS: usize = 128;
pub(crate) const MAX_ARTIFACTS: usize = 1;
pub(crate) const INTENT_SECONDS: u64 = 300;
pub(crate) const WORK_SECONDS: u64 = 3000;
pub(crate) const FINALITY_SECONDS: u64 = 3010;
const CONFIG_LIMIT: u32 = 512 * 1024;
const VERSION_LIMIT: u32 = 64 * 1024;
const AAB_LIMIT: u64 = 1024 * 1024 * 1024;
const DEPTH_LIMIT: usize = 16;
const NODE_LIMIT: usize = 8192;
const STRING_LIMIT: usize = 4096;
const SAFE_INTEGER: i64 = 9_007_199_254_740_991;

pub(crate) fn invalid() -> BridgeError {
    BridgeError::new("android_build_invalid", "The saved Android-build request is invalid.")
}
fn protocol_error() -> BridgeError {
    BridgeError::new("android_build_protocol", "The original Android-build response did not satisfy its fixed contract.")
}
fn keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len()
        && expected.iter().all(|key| object.contains_key(*key)))
}
fn sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// Serde performs JSON parsing. This small lexical check only excludes EVERY
// floating-point/exponent spelling, including 1e0: inspecting a parsed number
// alone would lose that distinction. Python admits integer -0 as zero, whereas
// serde_json visits it as f64; the bounded visitor handles that one spelling.
fn integer_lexemes(bytes: &[u8]) -> bool {
    let (mut index, mut string, mut escaped) = (0usize, false, false);
    while index < bytes.len() {
        let byte = bytes[index];
        if string {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { string = false; }
            index += 1;
            continue;
        }
        if byte == b'"' { string = true; index += 1; continue; }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            if byte == b'-' { index += 1; }
            let digits = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() { index += 1; }
            if index == digits || index - digits > 16 { return false; }
            if index < bytes.len() && !matches!(bytes[index], b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}') {
                return false;
            }
            let Ok(text) = std::str::from_utf8(&bytes[start..index]) else { return false; };
            if !text.parse::<i64>().is_ok_and(|n| (-SAFE_INTEGER..=SAFE_INTEGER).contains(&n)) { return false; }
            continue;
        }
        index += 1;
    }
    true
}

struct Seed<'a> { nodes: &'a mut usize, depth: usize }
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        *self.nodes += 1;
        if *self.nodes > NODE_LIMIT || self.depth > DEPTH_LIMIT {
            return Err(de::Error::custom("Android JSON bounds"));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("bounded Android DATA") }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> { Ok(Value::Bool(value)) }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        if !(-SAFE_INTEGER..=SAFE_INTEGER).contains(&value) { return Err(E::custom("Android integer bound")); }
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        if value > SAFE_INTEGER as u64 { return Err(E::custom("Android integer bound")); }
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        // integer_lexemes has already excluded decimal/exponent forms.
        if value == 0.0 && value.is_sign_negative() { Ok(Value::Number(0.into())) }
        else { Err(E::custom("Android integers only")) }
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > STRING_LIMIT { return Err(E::custom("Android string bound")); }
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        if value.len() > STRING_LIMIT { return Err(E::custom("Android string bound")); }
        Ok(Value::String(value))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed { nodes: self.nodes, depth: self.depth + 1 })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key_seed(Seed { nodes: self.nodes, depth: self.depth + 1 })? {
            let Value::String(key) = key else { return Err(de::Error::custom("Android object key")); };
            if values.contains_key(&key) { return Err(de::Error::custom("Android duplicate key")); }
            let value = map.next_value_seed(Seed { nodes: self.nodes, depth: self.depth + 1 })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
fn strict_data(bytes: &[u8], limit: usize, framed: bool) -> Result<Value, BridgeError> {
    if bytes.is_empty() || bytes.len() > limit || bytes.starts_with(&[0xef, 0xbb, 0xbf])
        || framed && (!bytes.ends_with(b"\n") || bytes.iter().filter(|b| **b == b'\n').count() != 1)
        || !integer_lexemes(bytes) { return Err(protocol_error()); }
    std::str::from_utf8(bytes).map_err(|_| protocol_error())?;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let mut nodes = 0;
    let value = Seed { nodes: &mut nodes, depth: 0 }.deserialize(&mut decoder).map_err(|_| protocol_error())?;
    decoder.end().map_err(|_| protocol_error())?;
    Ok(value)
}
fn structure(value: &Value) -> bool {
    fn visit(value: &Value, depth: usize, nodes: &mut usize) -> bool {
        *nodes += 1;
        if *nodes > NODE_LIMIT || depth > DEPTH_LIMIT { return false; }
        match value {
            Value::Null | Value::Bool(_) => true,
            Value::Number(n) => n.as_i64().is_some_and(|n| (-SAFE_INTEGER..=SAFE_INTEGER).contains(&n)),
            Value::String(text) => text.len() <= STRING_LIMIT,
            Value::Array(values) => values.iter().all(|value| visit(value, depth + 1, nodes)),
            Value::Object(values) => values.iter().all(|(key, value)| {
                *nodes += 1; // Keys, too, are nodes at depth+1 in the Python ABI.
                *nodes <= NODE_LIMIT && depth < DEPTH_LIMIT && key.len() <= STRING_LIMIT
                    && visit(value, depth + 1, nodes)
            }),
        }
    }
    visit(value, 0, &mut 0)
}
/// Only the original InvokeBody::Raw bytes may enter here, before DTO copying.
pub(crate) fn raw_request(bytes: &[u8]) -> Result<Value, BridgeError> {
    strict_data(bytes, IPC_LIMIT, false).map_err(|_| invalid())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Content { pub(crate) bytes: u32, pub(crate) sha256: String }
impl Content {
    fn valid(&self, maximum: u32) -> bool { (1..=maximum).contains(&self.bytes) && sha(&self.sha256) }
}

// Deliberately the existing release_version_protocol::relative_display_path
// TRANSPORT convention, not a second source-admission policy. The original core
// alone applies NFC/full-casefold/private-tree/source rules before any effect.
// Never normalize this comparison or use it as a Rust/native filesystem path.
fn relative_display_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 512 { return false; }
    let mut count = 0;
    for part in path.split('/') {
        count += 1;
        if count > 12 || part.is_empty() || part.len() > 255 || part.starts_with('.')
            || part.ends_with(['.', ' ']) || part.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}' || "\\:<>\"|?*".contains(c)) {
            return false;
        }
        let lower = part.to_lowercase();
        if ["private", "secrets", "credentials", "review", "testflight", "build", "deriveddata", "pods",
            "node_modules", "venv", "dist", "target", "__pycache__"].contains(&lower.as_str()) { return false; }
        let stem = lower.split('.').next().unwrap_or("");
        if ["con", "prn", "aux", "nul"].contains(&stem)
            || stem.len() == 4 && (stem.starts_with("com") || stem.starts_with("lpt")) && stem.as_bytes()[3].is_ascii_digit() {
            return false;
        }
    }
    true
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedVersion {
    pub(crate) source: String, pub(crate) bytes: u32, pub(crate) sha256: String,
    pub(crate) name: String, pub(crate) build: u32,
}
impl SavedVersion {
    fn valid(&self) -> bool {
        relative_display_path(&self.source) && (1..=VERSION_LIMIT).contains(&self.bytes) && sha(&self.sha256)
            && !self.name.is_empty() && self.name.len() <= 64
            && self.name.bytes().all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
            && (1..=2_100_000_000).contains(&self.build)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform { Android }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation { AndroidBuildInspect }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: SavedVersion,
    pub(crate) platform: Platform, pub(crate) operation: Operation,
}
impl Context {
    fn valid(&self) -> bool {
        valid_id(&self.project_id) && self.draft_revision < u32::MAX && self.baseline_generation < u32::MAX
            && self.saved_config.valid(CONFIG_LIMIT) && self.saved_version.valid()
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepare {
    pub(crate) project_id: String, pub(crate) draft_revision: u32, pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content, pub(crate) saved_version: SavedVersion,
}
impl Prepare {
    pub(crate) fn context(&self) -> Context {
        Context { project_id: self.project_id.clone(), draft_revision: self.draft_revision,
            baseline_generation: self.baseline_generation, saved_config: self.saved_config.clone(),
            saved_version: self.saved_version.clone(), platform: Platform::Android, operation: Operation::AndroidBuildInspect }
    }
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start {
    pub(crate) operation_id: String, pub(crate) owner_generation: String, consent_version: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel { pub(crate) operation_id: String, pub(crate) owner_generation: String }
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    if !structure(value) || !keys(value, &["projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion"]) {
        return Err(invalid());
    }
    let input = Prepare::deserialize(value).map_err(|_| invalid())?;
    if !input.context().valid() { return Err(invalid()); }
    bounded(value, IPC_LIMIT - 1).map_err(|_| invalid())?;
    Ok(input)
}
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    if !structure(value) || !keys(value, &["operationId", "ownerGeneration", "consentVersion"]) { return Err(invalid()); }
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) || input.consent_version != CONSENT { return Err(invalid()); }
    Ok(input)
}
pub(crate) fn cancel(value: &Value) -> Result<Cancel, BridgeError> {
    if !structure(value) || !keys(value, &["operationId", "ownerGeneration"]) { return Err(invalid()); }
    let input = Cancel::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) { return Err(invalid()); }
    Ok(input)
}
pub(crate) fn status_request(value: &Value) -> Result<(), BridgeError> {
    if keys(value, &[]) { Ok(()) } else { Err(invalid()) }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) enum Profile { #[serde(rename = "linux-gnu-x86_64")] LinuxX64 }
impl Profile {
    /// Host shape only; this is NEVER native/runtime/toolchain qualification.
    pub(crate) fn current() -> Option<Self> {
        if cfg!(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64")) { Some(Self::LinuxX64) } else { None }
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct RootIdentity {
    pub(crate) device: String, pub(crate) inode: String,
    pub(crate) mode: u32, pub(crate) uid: u32, pub(crate) gid: u32,
}
fn decimal(value: &str) -> bool {
    !value.is_empty() && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|b| b.is_ascii_digit()) && value.parse::<u64>().is_ok()
}
impl RootIdentity {
    fn valid(&self) -> bool {
        decimal(&self.device) && decimal(&self.inode) && self.inode != "0" && self.mode & 0o170000 == 0o040000
    }
}
fn native_path(path: &Path) -> Option<&str> {
    let text = path.to_str()?;
    if text.len() > 4096 || !text.starts_with('/') { return None; }
    if text != "/" {
        let mut count = 0;
        for part in text[1..].split('/') {
            count += 1;
            if count > 128 || part.is_empty() || matches!(part, "." | "..") || part.len() > 255
                || part.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}' || c == '\\' || c == ':') { return None; }
        }
    }
    Some(text)
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ToolchainBinding {
    schema_version: u32, profile: String, root: String, root_identity: RootIdentity, inventory_sha256: String,
}
impl ToolchainBinding {
    /// Native-owned caller supplies the original binding. This validates DATA
    /// only: no Deserialize/renderer constructor, filesystem operation or permit.
    /// Hashes and identity fields are NOT continuous tool/runtime custody.
    pub(crate) fn new_data(root: &Path, identity: RootIdentity, inventory_sha256: &str) -> Result<Self, BridgeError> {
        if !identity.valid() || !sha(inventory_sha256) { return Err(invalid()); }
        Ok(Self { schema_version: 1, profile: TOOLCHAIN_PROFILE.into(), root: native_path(root).ok_or_else(invalid)?.into(),
            root_identity: identity, inventory_sha256: inventory_sha256.into() })
    }
    fn valid(&self) -> bool {
        self.schema_version == 1 && self.profile == TOOLCHAIN_PROFILE && self.root_identity.valid()
            && sha(&self.inventory_sha256) && native_path(Path::new(&self.root)).is_some()
    }
}
/// Only an actual registered native project and a native-selected tool binding
/// enter this encoder. No savedVersion.source is used as a native path.
pub(crate) fn request(operation: &str, generation: &str, context: &Context, profile: Profile,
    project: &RegisteredRoot, cwd: &Path, toolchain: &ToolchainBinding) -> Result<Vec<u8>, BridgeError> {
    if !token(operation) || !token(generation) || !context.valid() || !toolchain.valid() { return Err(invalid()); }
    // Existing native identity projection is DATA; no offline permit is reused.
    let observed = project.identity.posix().map_err(|_| invalid())?.preflight_identity();
    let identity = RootIdentity { device: observed.device, inode: observed.inode, mode: observed.mode,
        uid: observed.uid, gid: observed.gid };
    if !identity.valid() { return Err(invalid()); }
    let value = json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,
            "rootIdentity":identity,"cwd":native_path(cwd).ok_or_else(invalid)?,"toolchain":toolchain}});
    if !structure(&value) { return Err(invalid()); }
    let mut bytes = bounded(&value, REQUEST_LIMIT - 1).map_err(|_| invalid())?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome { Complete, Refused, Failed, Cancelled, TimedOut, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None, Cancelled, ContextChanged, DocumentLost, Shutdown, TimedOut, ProtocolError, RuntimeUnavailable,
    IntentExpired, StaleIntent, SavedConfigMissing, SavedConfigInvalid, SavedConfigChanged, SavedConfigSensitive,
    SavedConfigUnsafe, SavedConfigTooLarge, SavedVersionMissing, SavedVersionInvalid, SavedVersionChanged,
    SavedVersionSensitive, SavedVersionUnsafe, SavedVersionTooLarge, PlatformDisabled, ModuleRequired,
    ToolchainUnavailable, ToolchainMismatch, ProjectAdmissionRefused, CommandFailed, CommandIncomplete,
    ArtifactMissing, ArtifactAmbiguous, ArtifactUnsafe, ArtifactChanged, InputLimit, ResultLimit, WorkRetained, CleanupUnknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage { Accepted, InputsBound, Building, Capturing, Inspecting, DisposingWork }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CommandOutcome { NotDispatched, Exited, Unknown }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CommandData { pub(crate) outcome: CommandOutcome, pub(crate) exit_code: Option<i32> }
impl CommandData {
    fn valid(&self) -> bool { (self.outcome == CommandOutcome::Exited) == self.exit_code.is_some() }
    fn zero(&self) -> bool { self.outcome == CommandOutcome::Exited && self.exit_code == Some(0) }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Selection {
    pub(crate) module: String, pub(crate) variant: String, pub(crate) application_id: String, pub(crate) task: String,
}
impl Selection {
    fn valid(&self) -> bool {
        fn label(text: &str, maximum: usize, punctuation: &[u8]) -> bool {
            !text.is_empty() && text.len() <= maximum && text.bytes().all(|b| b.is_ascii_alphanumeric() || punctuation.contains(&b))
        }
        let mut parts = self.application_id.split('.');
        let mut count = 0;
        let id = self.application_id.len() <= 255 && parts.all(|part| {
            count += 1;
            part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        }) && count >= 2;
        self.module.starts_with(':') && label(&self.module, 512, b"_.:-")
            && label(&self.variant, 128, b"_-") && id
            && self.task.len() >= 2 && self.task.starts_with(':') && label(&self.task, 648, b"_.:-")
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CoreStatus { Pass, Fail, Missing, Blocked, Invalid, Skip, Manual, Configured, NotApplicable }
const CORE_STATUSES: [CoreStatus; 9] = [CoreStatus::Pass, CoreStatus::Fail, CoreStatus::Missing, CoreStatus::Blocked,
    CoreStatus::Invalid, CoreStatus::Skip, CoreStatus::Manual, CoreStatus::Configured, CoreStatus::NotApplicable];
impl CoreStatus {
    fn failure(self) -> bool { matches!(self, Self::Fail | Self::Missing | Self::Blocked | Self::Invalid) }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CheckId { AabStructure, AabManifest, ApplicationId, BuildNumber, VersionName, ReleaseFlags, Signer, CoreLifecycle, OtherCoreFinding }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Finding { pub(crate) ordinal: u32, pub(crate) check: CheckId, pub(crate) status: CoreStatus }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Summary {
    pub(crate) total: u32, pub(crate) shown: u32, pub(crate) omitted: u32, pub(crate) counts: BTreeMap<CoreStatus, u32>,
}
fn inspection(findings: &[Finding], summary: &Summary) -> bool {
    if findings.len() > MAX_FINDINGS || summary.total as usize != findings.len() || summary.shown != summary.total
        || summary.omitted != 0 || summary.counts.len() != CORE_STATUSES.len() { return false; }
    let mut observed: BTreeMap<CoreStatus, u32> = CORE_STATUSES.into_iter().map(|status| (status, 0)).collect();
    for (ordinal, row) in findings.iter().enumerate() {
        if row.ordinal as usize != ordinal || row.check == CheckId::Signer && row.status != CoreStatus::Skip { return false; }
        *observed.entry(row.status).or_default() += 1;
    }
    observed == summary.counts
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Activity {
    pub(crate) stage: Stage, pub(crate) selection: Option<Selection>, pub(crate) command: CommandData,
    pub(crate) findings: Vec<Finding>, pub(crate) summary: Summary,
}
impl Activity {
    fn valid(&self) -> bool {
        if !self.command.valid() || self.selection.as_ref().is_some_and(|s| !s.valid()) || !inspection(&self.findings, &self.summary) {
            return false;
        }
        if matches!(self.stage, Stage::InputsBound | Stage::Building | Stage::Capturing | Stage::Inspecting) && self.selection.is_none() {
            return false;
        }
        if matches!(self.stage, Stage::Capturing | Stage::Inspecting) && !self.command.zero() { return false; }
        if self.command.outcome != CommandOutcome::NotDispatched && (self.selection.is_none()
            || !matches!(self.stage, Stage::Building | Stage::Capturing | Stage::Inspecting | Stage::DisposingWork)) { return false; }
        if self.findings.iter().any(|r| !matches!(r.check, CheckId::CoreLifecycle | CheckId::OtherCoreFinding))
            && (!self.command.zero() || !matches!(self.stage, Stage::Inspecting | Stage::DisposingWork)) { return false; }
        true
    }
}
fn activity_shape(value: &Value) -> bool {
    keys(value, &["stage", "selection", "command", "findings", "summary"])
        && value.get("command").is_some_and(|v| keys(v, &["outcome", "exitCode"]))
}

// Declaration order equals the Python ABI's lexicographically sorted ABI list.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Abi {
    #[serde(rename = "arm64-v8a")] Arm64V8a,
    #[serde(rename = "armeabi")] Armeabi,
    #[serde(rename = "armeabi-v7a")] ArmeabiV7a,
    #[serde(rename = "mips")] Mips,
    #[serde(rename = "mips64")] Mips64,
    #[serde(rename = "x86")] X86,
    #[serde(rename = "x86_64")] X86_64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Artifact {
    logical_name: String, platform: Platform, kind: String, file_name: String, size: u64, sha256: String,
    architectures: Vec<Abi>, unknown_abi: bool, freshness: String,
}
impl Artifact {
    fn valid(&self) -> bool {
        self.logical_name == "android-aab" && self.kind == "aab" && self.file_name == "app-release.aab"
            && (1..=AAB_LIMIT).contains(&self.size) && sha(&self.sha256) && self.architectures.len() <= 7
            && self.architectures.windows(2).all(|pair| pair[0] < pair[1]) && self.freshness == "not-established"
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum InspectionAssurance { Passed, Failed, NotChecked }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Assurances {
    structure: InspectionAssurance, native_manifest: InspectionAssurance, application_version: String,
    signer: String, toolkit_signing: String, store_operation: String, source_binding: String, release_readiness: String,
}
fn assurances(findings: &[Finding]) -> Assurances {
    let structure_rows: Vec<_> = findings.iter().filter(|r| r.check == CheckId::AabStructure).collect();
    let structure = if structure_rows.len() == 1 && structure_rows[0].status == CoreStatus::Pass { InspectionAssurance::Passed }
        else if structure_rows.iter().any(|r| r.status.failure()) { InspectionAssurance::Failed } else { InspectionAssurance::NotChecked };
    let manifest: Vec<_> = findings.iter().filter(|r| matches!(r.check, CheckId::AabManifest | CheckId::ApplicationId
        | CheckId::BuildNumber | CheckId::VersionName | CheckId::ReleaseFlags)).collect();
    let unsupported = findings.iter().any(|r| matches!(r.check, CheckId::OtherCoreFinding | CheckId::CoreLifecycle));
    let native = if structure == InspectionAssurance::Passed && !unsupported && manifest.len() == 1
        && manifest[0].check == CheckId::AabManifest && manifest[0].status == CoreStatus::Pass { InspectionAssurance::Passed }
        else if manifest.iter().any(|r| r.status.failure()) { InspectionAssurance::Failed } else { InspectionAssurance::NotChecked };
    Assurances { structure, native_manifest: native,
        application_version: if native == InspectionAssurance::Passed { "native-checked" } else { "not-established" }.into(),
        signer: "not-inspected".into(), toolkit_signing: "not-requested".into(), store_operation: "not-requested".into(),
        source_binding: "not-established".into(), release_readiness: "not-assessed".into() }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Limitation {
    SavedInputsNotAtomic, ProjectCodeEffectsPossible, NotNetworkIsolated, PostRunBytesMayBeIncrementalReusedOrStale,
    SourceBindingNotEstablished, ArtifactSignerNotInspected, ToolkitSigningNotRequested, StoreOperationNotRequested,
    ReleaseReadinessNotAssessed, LocalOutputObservationNotCurrentFileAuthority, CoreTerminalRequiresOriginalNativeFinality,
}
const LIMITATIONS: [Limitation; 11] = [Limitation::SavedInputsNotAtomic, Limitation::ProjectCodeEffectsPossible,
    Limitation::NotNetworkIsolated, Limitation::PostRunBytesMayBeIncrementalReusedOrStale, Limitation::SourceBindingNotEstablished,
    Limitation::ArtifactSignerNotInspected, Limitation::ToolkitSigningNotRequested, Limitation::StoreOperationNotRequested,
    Limitation::ReleaseReadinessNotAssessed, Limitation::LocalOutputObservationNotCurrentFileAuthority,
    Limitation::CoreTerminalRequiresOriginalNativeFinality];
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultData {
    schema_version: u32, scope: String, used_config: Content, used_version: SavedVersion, selection: Selection,
    toolchain_profile: String, command: CommandData, findings: Vec<Finding>, summary: Summary,
    artifacts: Vec<Artifact>, assurances: Assurances, limitations: Vec<Limitation>,
}
impl ResultData {
    fn valid(&self) -> bool {
        self.schema_version == 1 && self.scope == SCOPE && self.used_config.valid(CONFIG_LIMIT) && self.used_version.valid()
            && self.selection.valid() && self.toolchain_profile == TOOLCHAIN_PROFILE && self.command.zero()
            && inspection(&self.findings, &self.summary) && self.findings.iter().any(|r| r.check == CheckId::AabStructure)
            && self.findings.iter().all(|r| r.check != CheckId::CoreLifecycle) && self.artifacts.len() == MAX_ARTIFACTS
            && self.artifacts.iter().all(Artifact::valid) && self.assurances == assurances(&self.findings)
            && self.limitations.as_slice() == LIMITATIONS
    }
    fn matches(&self, context: &Context, activity: &Activity) -> bool {
        self.used_config == context.saved_config && self.used_version == context.saved_version
            && activity.selection.as_ref() == Some(&self.selection) && self.command == activity.command
            && self.findings == activity.findings && self.summary == activity.summary
    }
}
fn result_shape(value: &Value) -> bool {
    keys(value, &["schemaVersion", "scope", "usedConfig", "usedVersion", "selection", "toolchainProfile", "command",
        "findings", "summary", "artifacts", "assurances", "limitations"])
        && value.get("command").is_some_and(|v| keys(v, &["outcome", "exitCode"]))
}
pub(crate) fn result(value: &Value) -> Result<ResultData, BridgeError> {
    if !structure(value) || !result_shape(value) { return Err(protocol_error()); }
    let result = ResultData::deserialize(value).map_err(|_| protocol_error())?;
    if !result.valid() { return Err(protocol_error()); }
    bounded(value, RESPONSE_LIMIT - 1).map_err(|_| protocol_error())?;
    Ok(result)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WorkDisposition { NotCreated, Removed, RetainedWork, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ArtifactDisposition { NotCreated, Removed, RetainedLocalResult, RetainedIncomplete, Unknown }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Disposition { pub(crate) work: WorkDisposition, pub(crate) artifacts: ArtifactDisposition }
impl Disposition {
    fn known(&self) -> bool { self.work != WorkDisposition::Unknown && self.artifacts != ArtifactDisposition::Unknown }
    fn complete(&self) -> bool { self.work == WorkDisposition::Removed && self.artifacts == ArtifactDisposition::RetainedLocalResult }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CoreStop { None, Cancelled, TimedOut }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Lifetime {
    pub(crate) complete: bool, pub(crate) fatal: bool, pub(crate) contained: bool,
    pub(crate) command_dispatched: Option<bool>, pub(crate) commands: u32, pub(crate) profile_calls: u32,
    pub(crate) input_closed: bool, pub(crate) handlers_restored: bool, pub(crate) invocation_closed: bool,
    pub(crate) artifacts_closed: bool, pub(crate) tools_closed: bool, pub(crate) namespace_closed: bool,
    pub(crate) stop_observed: CoreStop,
}
impl Lifetime {
    fn valid(&self) -> bool { self.commands <= 2 && self.profile_calls == 0 }
    pub(crate) fn settled(&self) -> bool {
        self.valid() && self.complete && !self.fatal && self.contained && self.command_dispatched.is_some()
            && self.input_closed && self.handlers_restored && self.invocation_closed && self.artifacts_closed
            && self.tools_closed && self.namespace_closed
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Terminal {
    schema_version: u32, context: Context, pub(crate) outcome: Outcome, pub(crate) reason: Reason,
    pub(crate) activity: Activity, pub(crate) disposition: Disposition, pub(crate) result: Option<ResultData>,
    pub(crate) lifetime: Lifetime,
}
fn artifact_reason(reason: Reason) -> bool {
    matches!(reason, Reason::ArtifactMissing | Reason::ArtifactAmbiguous | Reason::ArtifactUnsafe | Reason::ArtifactChanged)
}
fn failure_facts(outcome: Outcome, reason: Reason, activity: &Activity, disposition: &Disposition) -> bool {
    if outcome == Outcome::Refused && activity.command.outcome != CommandOutcome::NotDispatched { return false; }
    if reason == Reason::CommandFailed && (outcome != Outcome::Failed || activity.command.outcome != CommandOutcome::Exited
        || activity.command.exit_code == Some(0)) { return false; }
    if reason == Reason::CommandIncomplete && (outcome != Outcome::Failed || activity.command.outcome == CommandOutcome::Exited) {
        return false;
    }
    if artifact_reason(reason) && (outcome != Outcome::Failed || activity.selection.is_none() || !activity.command.zero()
        || !matches!(activity.stage, Stage::Capturing | Stage::Inspecting | Stage::DisposingWork)) { return false; }
    if reason == Reason::WorkRetained && (outcome != Outcome::Failed || disposition.work != WorkDisposition::RetainedWork) { return false; }
    disposition.work != WorkDisposition::RetainedWork || matches!(outcome, Outcome::Failed | Outcome::Unknown)
}
impl Terminal {
    /// Core ledger/disposition predicate ONLY. Original native joins remain
    /// mandatory; this method cannot authorize publication or resource release.
    pub(crate) fn settled(&self) -> bool { self.lifetime.settled() && self.disposition.known() }
    fn valid(&self, context: &Context) -> bool {
        if self.schema_version != 1 || &self.context != context || !context.valid() || !self.activity.valid() || !self.lifetime.valid() {
            return false;
        }
        let life = &self.lifetime;
        match self.activity.command.outcome {
            CommandOutcome::NotDispatched if life.command_dispatched != Some(false) || life.commands > 1 => return false,
            CommandOutcome::Exited if life.command_dispatched != Some(true) || life.commands < 1 => return false,
            _ => {},
        }
        if self.outcome == Outcome::Complete {
            return self.settled() && life.stop_observed == CoreStop::None && self.reason == Reason::None
                && self.activity.stage == Stage::DisposingWork && self.disposition.complete()
                && self.result.as_ref().is_some_and(|r| r.valid() && r.matches(context, &self.activity)
                    && (r.assurances.native_manifest != InspectionAssurance::Passed || life.commands == 2));
        }
        if self.result.is_some() || self.reason == Reason::None || self.disposition.artifacts == ArtifactDisposition::RetainedLocalResult {
            return false;
        }
        if self.outcome == Outcome::Unknown {
            if self.reason != Reason::CleanupUnknown || self.settled() { return false; }
        } else if !self.settled() || self.reason == Reason::CleanupUnknown { return false; }
        match self.outcome {
            Outcome::Cancelled if self.reason != Reason::Cancelled || life.stop_observed != CoreStop::Cancelled => return false,
            Outcome::TimedOut if self.reason != Reason::TimedOut || life.stop_observed != CoreStop::TimedOut => return false,
            Outcome::Refused if life.command_dispatched != Some(false) => return false,
            _ => {},
        }
        if matches!(self.reason, Reason::Cancelled | Reason::ContextChanged | Reason::DocumentLost | Reason::Shutdown)
            && life.stop_observed != CoreStop::Cancelled { return false; }
        if self.reason == Reason::TimedOut && life.stop_observed != CoreStop::TimedOut { return false; }
        failure_facts(self.outcome, self.reason, &self.activity, &self.disposition)
    }
}
fn terminal_shape(value: &Value) -> bool {
    keys(value, &["schemaVersion", "context", "outcome", "reason", "activity", "disposition", "result", "lifetime"])
        && value.get("activity").is_some_and(activity_shape)
        && value.get("lifetime").is_some_and(|v| keys(v, &["complete", "fatal", "contained", "commandDispatched", "commands",
            "profileCalls", "stopObserved", "inputClosed", "handlersRestored", "invocationClosed", "artifactsClosed", "toolsClosed", "namespaceClosed"]))
        && value.get("result").is_some_and(|v| v.is_null() || result_shape(v))
}
pub(crate) fn terminal(value: &Value, context: &Context) -> Result<Terminal, BridgeError> {
    if !structure(value) || !terminal_shape(value) { return Err(protocol_error()); }
    let terminal = Terminal::deserialize(value).map_err(|_| protocol_error())?;
    if !terminal.valid(context) { return Err(protocol_error()); }
    bounded(value, RESPONSE_LIMIT - 1).map_err(|_| protocol_error())?;
    Ok(terminal)
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

/// One finite decoder belongs in the original stdout reader. It owns only DATA,
/// not a pipe, timeout, owner or retry permit. The native reader must separately
/// charge ALL stdout/stderr bytes, reject ANY stderr, drain originals on error,
/// and preserve their actual EOF/close records even after this decoder fails.
pub(crate) struct FrameDecoder {
    operation: String, generation: String, context: Context,
    frames: usize, bytes: usize, stage: Stage, terminal: bool, failed: bool,
}
impl FrameDecoder {
    pub(crate) fn new(operation: &str, generation: &str, context: &Context) -> Result<Self, BridgeError> {
        if !token(operation) || !token(generation) || !context.valid() { return Err(protocol_error()); }
        Ok(Self { operation: operation.into(), generation: generation.into(), context: context.clone(),
            frames: 0, bytes: 0, stage: Stage::Accepted, terminal: false, failed: false })
    }
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<Frame, BridgeError> {
        self.bytes = self.bytes.saturating_add(bytes.len());
        let result = self.push_original(bytes);
        if result.is_err() { self.failed = true; }
        result
    }
    fn push_original(&mut self, bytes: &[u8]) -> Result<Frame, BridgeError> {
        if self.failed || self.terminal || self.frames >= MAX_FRAMES || self.bytes > RESPONSE_LIMIT { return Err(protocol_error()); }
        let value = strict_data(bytes, RESPONSE_LIMIT, true)?;
        let envelope = Envelope::deserialize(&value).map_err(|_| protocol_error())?;
        if envelope.protocol != PROTOCOL || envelope.operation_id != self.operation || envelope.owner_generation != self.generation
            || envelope.sequence as usize != self.frames { return Err(protocol_error()); }
        let frame = match envelope.kind.as_str() {
            "accepted" if self.frames == 0 => {
                let accepted = Accepted::deserialize(&envelope.payload).map_err(|_| protocol_error())?;
                if accepted.schema_version != 1 || accepted.context != self.context || !accepted.context.valid() { return Err(protocol_error()); }
                Frame::Accepted
            },
            "progress" if (1..=5).contains(&self.frames) => {
                let progress = Progress::deserialize(&envelope.payload).map_err(|_| protocol_error())?;
                if progress.schema_version != 1 || progress.stage <= self.stage { return Err(protocol_error()); }
                Frame::Progress(progress.stage)
            },
            "terminal" if self.frames >= 1 => {
                let terminal = terminal(&envelope.payload, &self.context)?;
                if terminal.activity.stage < self.stage { return Err(protocol_error()); }
                Frame::Terminal(terminal)
            },
            _ => return Err(protocol_error()),
        };
        self.frames += 1;
        match &frame {
            Frame::Progress(stage) => self.stage = *stage,
            Frame::Terminal(_) => self.terminal = true,
            Frame::Accepted => {},
        }
        Ok(frame)
    }
    /// Called on observed original EOF; this does not observe or close IO itself.
    pub(crate) fn finish(&mut self) -> Result<(), BridgeError> {
        if !self.settled() { self.failed = true; Err(protocol_error()) } else { Ok(()) }
    }
    pub(crate) fn settled(&self) -> bool { !self.failed && self.terminal && (2..=MAX_FRAMES).contains(&self.frames) }
    pub(crate) fn frames(&self) -> usize { self.frames }
    pub(crate) fn bytes(&self) -> usize { self.bytes }
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
    pub(crate) phase: Phase, pub(crate) intent_usable: bool, pub(crate) outcome: Option<Outcome>, pub(crate) reason: Reason,
    pub(crate) stage: Option<Stage>, pub(crate) activity: Option<Activity>, pub(crate) disposition: Option<Disposition>,
    pub(crate) result: Option<ResultData>,
}
impl Projection {
    fn valid(&self) -> bool {
        if !token(&self.operation_id) || !token(&self.owner_generation) || !self.context.valid() { return false; }
        let empty_pair = self.activity.is_none() && self.disposition.is_none();
        match self.phase {
            Phase::AwaitingConsent => self.outcome.is_none() && self.reason == Reason::None && self.stage.is_none()
                && self.result.is_none() && empty_pair,
            Phase::Starting | Phase::Running | Phase::Stopping => !self.intent_usable && self.outcome.is_none()
                && self.result.is_none() && empty_pair && (self.phase != Phase::Starting || self.stage.is_none()),
            Phase::Unknown => !self.intent_usable && self.outcome == Some(Outcome::Unknown) && self.reason == Reason::CleanupUnknown
                && self.result.is_none() && empty_pair,
            Phase::Terminal => {
                if self.intent_usable { return false; }
                let Some(outcome) = self.outcome else { return false; };
                if outcome == Outcome::Unknown || (self.reason == Reason::None) != (outcome == Outcome::Complete) { return false; }
                if outcome == Outcome::Complete {
                    return self.stage == Some(Stage::DisposingWork)
                        && self.activity.as_ref().is_some_and(|activity| activity.valid() && activity.stage == Stage::DisposingWork
                            && self.result.as_ref().is_some_and(|result| result.valid() && result.matches(&self.context, activity)))
                        && self.disposition.as_ref().is_some_and(Disposition::complete);
                }
                // Original native retirement preserves its first reason. This
                // is deliberately broader than the Python/Core Terminal rule:
                // changing a prepared context may retire without any core run.
                if self.result.is_some() || self.reason == Reason::CleanupUnknown
                    || outcome == Outcome::Cancelled && !matches!(self.reason,
                        Reason::Cancelled | Reason::ContextChanged | Reason::DocumentLost | Reason::Shutdown)
                    || outcome == Outcome::TimedOut && self.reason != Reason::TimedOut { return false; }
                match (&self.activity, &self.disposition) {
                    (Some(activity), Some(disposition)) => activity.valid() && self.stage == Some(activity.stage)
                        && disposition.known() && disposition.artifacts != ArtifactDisposition::RetainedLocalResult
                        && failure_facts(outcome, self.reason, activity, disposition),
                    (None, None) => !matches!(self.reason, Reason::CommandFailed | Reason::CommandIncomplete | Reason::WorkRetained)
                        && !artifact_reason(self.reason),
                    _ => false,
                }
            },
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    pub(crate) schema_version: u32, pub(crate) status_revision: u32, pub(crate) availability: Availability,
    pub(crate) operation: Option<Projection>,
}
fn projection_shape(value: &Value) -> bool {
    keys(value, &["operationId", "ownerGeneration", "context", "phase", "intentUsable", "outcome", "reason", "stage", "activity", "disposition", "result"])
        && value.get("activity").is_some_and(|v| v.is_null() || activity_shape(v))
        && value.get("result").is_some_and(|v| v.is_null() || result_shape(v))
}
/// Status is native projection DATA, not the core terminal and not a renderer
/// acknowledgment. No method here decides when native joins permit publication.
pub(crate) fn status(value: &Value) -> Result<Status, BridgeError> {
    if !structure(value) || !keys(value, &["schemaVersion", "statusRevision", "availability", "operation"])
        || !value.get("operation").is_some_and(|v| v.is_null() || projection_shape(v)) { return Err(protocol_error()); }
    let status = Status::deserialize(value).map_err(|_| protocol_error())?;
    if status.schema_version != 1 || status.status_revision == u32::MAX || status.operation.as_ref().is_some_and(|p| !p.valid()) {
        return Err(protocol_error());
    }
    bounded(value, STATUS_LIMIT).map_err(|_| protocol_error())?;
    Ok(status)
}
pub(crate) fn status_bytes(value: &Status) -> Result<Vec<u8>, BridgeError> {
    // Bound serialization BEFORE allocating a second tree. Even trusted native
    // code must not accidentally materialize an unbounded status projection.
    let bytes = bounded(value, STATUS_LIMIT).map_err(|_| protocol_error())?;
    let data = strict_data(&bytes, STATUS_LIMIT, false)?;
    status(&data)?;
    Ok(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    // These fixtures are invented predicate DATA, never file/process/cleanup
    // evidence or qualification. No filesystem, native runtime or owner is used.
    use super::*;

    fn prepare_value() -> Value {
        json!({"projectId":"inert-android","draftRevision":2,"baselineGeneration":3,
            "savedConfig":{"bytes":512,"sha256":"c".repeat(64)},
            "savedVersion":{"source":"release/version.properties","bytes":41,"sha256":"d".repeat(64),"name":"1.2.3","build":42}})
    }
    pub(crate) fn context() -> Context { prepare(&prepare_value()).unwrap().context() }
    fn selection() -> Value {
        json!({"module":":app","variant":"release","applicationId":"org.example.app","task":":app:bundleRelease"})
    }
    fn rows(entries: &[(&str, &str)]) -> (Value, Value) {
        let mut counts = json!({"PASS":0,"FAIL":0,"MISSING":0,"BLOCKED":0,"INVALID":0,"SKIP":0,
            "MANUAL":0,"CONFIGURED":0,"NOT_APPLICABLE":0});
        let findings: Vec<_> = entries.iter().enumerate().map(|(ordinal, (check, status))| {
            counts[*status] = json!(counts[*status].as_u64().unwrap() + 1);
            json!({"ordinal":ordinal,"check":check,"status":status})
        }).collect();
        (json!(findings), json!({"total":entries.len(),"shown":entries.len(),"omitted":0,"counts":counts}))
    }
    fn complete() -> Value {
        let context = context();
        let (findings, summary) = rows(&[("aab-structure", "PASS"), ("aab-manifest", "PASS"), ("signer", "SKIP")]);
        let command = json!({"outcome":"exited","exitCode":0});
        let activity = json!({"stage":"disposing-work","selection":selection(),"command":command,
            "findings":findings,"summary":summary});
        let result = json!({"schemaVersion":1,"scope":SCOPE,"usedConfig":context.saved_config,"usedVersion":context.saved_version,
            "selection":selection(),"toolchainProfile":TOOLCHAIN_PROFILE,"command":command,"findings":findings,"summary":summary,
            "artifacts":[{"logicalName":"android-aab","platform":"android","kind":"aab","fileName":"app-release.aab",
                "size":1024,"sha256":"f".repeat(64),"architectures":["arm64-v8a"],"unknownAbi":false,"freshness":"not-established"}],
            "assurances":{"structure":"passed","nativeManifest":"passed","applicationVersion":"native-checked","signer":"not-inspected",
                "toolkitSigning":"not-requested","storeOperation":"not-requested","sourceBinding":"not-established","releaseReadiness":"not-assessed"},
            "limitations":["saved-inputs-not-atomic","project-code-effects-possible","not-network-isolated",
                "post-run-bytes-may-be-incremental-reused-or-stale","source-binding-not-established","artifact-signer-not-inspected",
                "toolkit-signing-not-requested","store-operation-not-requested","release-readiness-not-assessed",
                "local-output-observation-not-current-file-authority","core-terminal-requires-original-native-finality"]});
        json!({"schemaVersion":1,"context":context,"outcome":"complete","reason":"none","activity":activity,
            "disposition":{"work":"removed","artifacts":"retained-local-result"},"result":result,
            "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":2,"profileCalls":0,
                "inputClosed":true,"handlersRestored":true,"invocationClosed":true,"artifactsClosed":true,"toolsClosed":true,
                "namespaceClosed":true,"stopObserved":"none"}})
    }
    fn set_rows(value: &mut Value, entries: &[(&str, &str)], structure: &str, native: &str) {
        let (findings, summary) = rows(entries);
        value["activity"]["findings"] = findings.clone();
        value["activity"]["summary"] = summary.clone();
        if !value["result"].is_null() {
            value["result"]["findings"] = findings;
            value["result"]["summary"] = summary;
            value["result"]["assurances"]["structure"] = json!(structure);
            value["result"]["assurances"]["nativeManifest"] = json!(native);
            value["result"]["assurances"]["applicationVersion"] = json!(if native == "passed" { "native-checked" } else { "not-established" });
        }
    }
    fn failed(code: i32) -> Value {
        let mut value = complete();
        value["outcome"] = json!("failed"); value["reason"] = json!("command-failed"); value["result"] = Value::Null;
        value["activity"]["command"]["exitCode"] = json!(code);
        set_rows(&mut value, &[], "not-checked", "not-checked");
        value["disposition"]["artifacts"] = json!("not-created"); value["lifetime"]["commands"] = json!(1);
        value
    }
    // Reused by the shared-owner INERT tests so they need not invent a second
    // Android ABI fixture. These return DATA, never an ownership/cleanup receipt.
    pub(crate) fn complete_terminal() -> Value { complete() }
    pub(crate) fn negative_terminal(exit_code: i32) -> Value { failed(exit_code) }
    pub(crate) fn complete_with_failed_inspection() -> Value {
        let mut value = complete();
        set_rows(&mut value, &[("aab-structure", "FAIL"), ("aab-manifest", "SKIP"), ("signer", "SKIP")], "failed", "not-checked");
        value["lifetime"]["commands"] = json!(1);
        value
    }
    fn refused() -> Value {
        let mut value = failed(7);
        value["outcome"] = json!("refused"); value["reason"] = json!("toolchain-unavailable");
        value["activity"]["stage"] = json!("accepted"); value["activity"]["selection"] = Value::Null;
        value["activity"]["command"] = json!({"outcome":"not-dispatched","exitCode":null});
        value["disposition"]["work"] = json!("not-created");
        value["lifetime"]["commandDispatched"] = json!(false); value["lifetime"]["commands"] = json!(0);
        value
    }
    fn unknown() -> Value {
        let mut value = failed(7);
        value["outcome"] = json!("unknown"); value["reason"] = json!("cleanup-unknown");
        value["activity"]["command"] = json!({"outcome":"unknown","exitCode":null});
        value["lifetime"]["commandDispatched"] = Value::Null; value["lifetime"]["complete"] = json!(false);
        value["disposition"]["work"] = json!("unknown");
        value
    }
    fn parse_terminal(value: &Value) -> Result<Terminal, BridgeError> { terminal(value, &context()) }
    fn frame(sequence: u32, kind: &str, payload: Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({"protocol":PROTOCOL,"operationId":"a".repeat(32),
            "ownerGeneration":"b".repeat(32),"sequence":sequence,"kind":kind,"payload":payload})).unwrap();
        bytes.push(b'\n'); bytes
    }
    fn accepted() -> Vec<u8> { frame(0, "accepted", json!({"schemaVersion":1,"context":context()})) }
    fn progress(sequence: u32, stage: &str) -> Vec<u8> { frame(sequence, "progress", json!({"schemaVersion":1,"stage":stage})) }
    fn decoder() -> FrameDecoder { FrameDecoder::new(&"a".repeat(32), &"b".repeat(32), &context()).unwrap() }
    fn native_complete() -> Value {
        let core = complete();
        json!({"schemaVersion":1,"statusRevision":7,"availability":"available","operation":{
            "operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"context":core["context"],"phase":"terminal",
            "intentUsable":false,"outcome":"complete","reason":"none","stage":"disposing-work",
            "activity":core["activity"],"disposition":core["disposition"],"result":core["result"]}})
    }

    #[test]
    fn fixed_domain_and_limits_do_not_admit_offline_or_extra_artifacts() {
        assert_eq!(PROTOCOL, "mrk-android-build/1");
        assert_eq!(CONSENT, "saved-android-build-inspect-v1");
        assert_eq!(EVENT, "android-build-state-changed");
        assert_eq!((IPC_LIMIT, REQUEST_LIMIT, RESPONSE_LIMIT, STATUS_LIMIT), (8192, 32768, 65536, 65536));
        assert_eq!((MAX_FRAMES, MAX_FINDINGS, MAX_ARTIFACTS), (8, 128, 1));
        assert_eq!((INTENT_SECONDS, WORK_SECONDS, FINALITY_SECONDS), (300, 3000, 3010));
        assert_eq!(serde_json::to_value(Profile::LinuxX64).unwrap(), json!("linux-gnu-x86_64"));
        let good = complete();
        assert_eq!(serde_json::to_value(LIMITATIONS).unwrap(), good["result"]["limitations"]);
        assert_eq!(parse_terminal(&good).unwrap().outcome, Outcome::Complete);
        let mut other = good;
        other["context"]["operation"] = json!("offline-preflight"); assert!(parse_terminal(&other).is_err());
    }

    #[test]
    fn original_raw_limits_duplicates_encoding_and_numeric_spellings_are_strict() {
        let mut boundary = vec![b' '; IPC_LIMIT - 2]; boundary.extend_from_slice(b"{}");
        assert!(status_request(&raw_request(&boundary).unwrap()).is_ok());
        boundary.push(b' '); assert!(raw_request(&boundary).is_err());
        for raw in [b"".as_slice(), b"{\"PRIVATE\":1,\"PRIVATE\":2}", b"{\"x\":{\"a\":1,\"a\":2}}",
            b"{\"x\":1.0}", b"{\"x\":1e0}", b"{\"x\":-0.0}", b"{\"x\":NaN}", b"{\"x\":Infinity}",
            b"{\"x\":9007199254740992}", b"{\"x\":-9007199254740992}", b"{\"x\":000}",
            b"\xef\xbb\xbf{}", b"{\"x\":\"\\ud800\"}", b"{} trailing", &[0xff]] {
            let error = raw_request(raw).unwrap_err();
            assert_eq!(error, invalid()); assert!(!error.to_string().contains("PRIVATE"));
        }
        // A negative-zero INTEGER is exactly Python's int(\"-0\") == 0;
        // fractional/exponent spellings above never reach this conversion.
        assert_eq!(raw_request(b"{\"x\":-0}").unwrap(), json!({"x":0}));
        assert_eq!(raw_request(b"{\"x\":9007199254740991}").unwrap(), json!({"x":SAFE_INTEGER}));
        assert_eq!(raw_request(b"{\"x\":\"123e4\"}").unwrap(), json!({"x":"123e4"}));
    }

    #[test]
    fn json_depth_keys_nodes_and_utf8_bytes_are_charged_before_retention() {
        let mut nested = Value::Null;
        for _ in 0..DEPTH_LIMIT { nested = json!([nested]); }
        assert!(strict_data(&serde_json::to_vec(&nested).unwrap(), RESPONSE_LIMIT, false).is_ok());
        nested = json!([nested]);
        assert!(strict_data(&serde_json::to_vec(&nested).unwrap(), RESPONSE_LIMIT, false).is_err());
        let values = json!(vec![0; NODE_LIMIT - 1]);
        assert!(strict_data(&serde_json::to_vec(&values).unwrap(), RESPONSE_LIMIT, false).is_ok());
        let values = json!(vec![0; NODE_LIMIT]);
        assert!(strict_data(&serde_json::to_vec(&values).unwrap(), RESPONSE_LIMIT, false).is_err());
        for (value, allowed) in [(json!("x".repeat(STRING_LIMIT)), true), (json!("x".repeat(STRING_LIMIT + 1)), false),
            (json!("é".repeat(STRING_LIMIT / 2)), true), (json!("é".repeat(STRING_LIMIT / 2 + 1)), false)] {
            assert_eq!(strict_data(&serde_json::to_vec(&value).unwrap(), RESPONSE_LIMIT, false).is_ok(), allowed);
        }
        let mut object = Map::new(); object.insert("x".repeat(STRING_LIMIT + 1), Value::Null);
        assert!(strict_data(&serde_json::to_vec(&object).unwrap(), RESPONSE_LIMIT, false).is_err());
    }

    #[test]
    fn prepare_is_saved_comparison_data_not_draft_native_selection_or_version_policy() {
        let good = prepare_value(); assert!(prepare(&good).is_ok());
        for field in ["native", "root", "argv", "environment", "module", "variant", "signed", "toolchain", "draft"] {
            let mut bad = good.clone(); bad[field] = json!("PRIVATE"); assert!(prepare(&bad).is_err());
        }
        for field in ["draftRevision", "baselineGeneration"] {
            for bad in [json!(true), json!(-1), json!(u32::MAX), json!(2.0), json!("2")] {
                let mut value = good.clone(); value[field] = bad; assert!(prepare(&value).is_err());
            }
        }
        for source in ["/PRIVATE", "../version.properties", "release//version.properties", "release/.env", "release/credentials/v",
            "release/COM0.properties", "release/aux.txt", "release/name.", "release/name ", "release/a:b", "release/a\\b"] {
            let mut bad = good.clone(); bad["savedVersion"]["source"] = json!(source); assert!(prepare(&bad).is_err());
        }
        for (field, bad) in [("bytes", json!(0)), ("bytes", json!(VERSION_LIMIT + 1)), ("sha256", json!("D".repeat(64))),
            ("build", json!(0)), ("build", json!(2_100_000_001u64)), ("build", json!(true)), ("name", json!("x".repeat(65)))] {
            let mut value = good.clone(); value["savedVersion"][field] = bad; assert!(prepare(&value).is_err());
        }
        let mut value = good;
        value["savedVersion"]["name"] = json!("not-a-marketing-version");
        // Native performs no release policy and never normalizes the source.
        let source = "release/e\u{301}.properties";
        value["savedVersion"]["source"] = json!(source);
        assert_eq!(prepare(&value).unwrap().saved_version.source, source);
        assert_eq!(prepare(&value).unwrap().saved_version.name, "not-a-marketing-version");
    }

    #[test]
    fn start_and_cancel_are_closed_ids_not_an_execution_or_one_use_receipt() {
        let good = json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32),"consentVersion":CONSENT});
        // Parsing twice is deliberately only DATA; the original owner must burn consent.
        assert!(start(&good).is_ok()); assert!(start(&good).is_ok());
        let mut wrong = good.clone(); wrong["consentVersion"] = json!("saved-offline-android-v1"); assert!(start(&wrong).is_err());
        for id in ["a".repeat(31), "A".repeat(32), "a".repeat(33), "../PRIVATE".into()] {
            let mut wrong = good.clone(); wrong["operationId"] = json!(id); assert!(start(&wrong).is_err());
        }
        assert!(cancel(&json!({"operationId":"a".repeat(32),"ownerGeneration":"b".repeat(32)})).is_ok());
        assert!(cancel(&good).is_err()); assert!(status_request(&json!({"projectId":"inert-android"})).is_err());
    }

    #[test]
    fn native_tool_binding_encodes_only_data_and_never_reuses_a_fixture_permit() {
        let identity = RootIdentity { device: "1".into(), inode: "2".into(), mode: 0o40700, uid: 123, gid: 123 };
        let tool = ToolchainBinding::new_data(Path::new("/PRIVATE_TOOLS"), identity.clone(), &"e".repeat(64)).unwrap();
        // Existing synthetic identity is used ONLY as a serialization predicate;
        // no fixture registration, permit, native open or launch is invoked.
        let project = RegisteredRoot { path: "/PRIVATE_PROJECT".into(),
            identity: crate::asset_source::ProjectIdentity::Posix(crate::asset_source::DirectoryIdentity::synthetic_evidence_identity()) };
        let bytes = request(&"a".repeat(32), &"b".repeat(32), &context(), Profile::LinuxX64,
            &project, Path::new("/PRIVATE_CWD"), &tool).unwrap();
        let value = strict_data(&bytes, REQUEST_LIMIT, true).unwrap();
        assert_eq!(value["native"]["projectRoot"], "/PRIVATE_PROJECT");
        assert_eq!(value["native"]["cwd"], "/PRIVATE_CWD");
        assert_eq!(value["native"]["toolchain"], json!({"schemaVersion":1,"profile":TOOLCHAIN_PROFILE,
            "root":"/PRIVATE_TOOLS","rootIdentity":{"device":"1","inode":"2","mode":0o40700,"uid":123,"gid":123},
            "inventorySha256":"e".repeat(64)}));
        assert!(bytes.len() <= REQUEST_LIMIT && bytes.ends_with(b"\n"));
        assert!(!value["native"].as_object().unwrap().contains_key("qualified"));
        let mut windows = project.clone();
        windows.identity = crate::asset_source::ProjectIdentity::Windows { volume: u64::MAX, file_id: [0xff; 16] };
        assert!(request(&"a".repeat(32), &"b".repeat(32), &context(), Profile::LinuxX64,
            &windows, Path::new("/PRIVATE_CWD"), &tool).is_err());
        assert!(ToolchainBinding::new_data(Path::new("../PRIVATE"), identity.clone(), &"e".repeat(64)).is_err());
        for path in ["/a//b", "/a/../b", "/a/./b", "/a\\b", "/a:b", "/a\nb"] {
            assert!(ToolchainBinding::new_data(Path::new(path), identity.clone(), &"e".repeat(64)).is_err());
        }
        for (device, inode, mode) in [("01", "2", 0o40700), ("1", "0", 0o40700),
            ("18446744073709551616", "2", 0o40700), ("1", "2", 0o100600)] {
            let bad = RootIdentity { device: device.into(), inode: inode.into(), mode, uid: 123, gid: 123 };
            assert!(ToolchainBinding::new_data(Path::new("/PRIVATE_TOOLS"), bad, &"e".repeat(64)).is_err());
        }
        let mut bad = tool; bad.profile = "other-profile".into();
        assert!(request(&"a".repeat(32), &"b".repeat(32), &context(), Profile::LinuxX64,
            &project, Path::new("/PRIVATE_CWD"), &bad).is_err());
    }

    #[test]
    fn complete_binds_both_exact_byte_pairs_source_and_displayed_version() {
        let good = complete(); assert!(parse_terminal(&good).is_ok());
        for (container, field, changed) in [("usedConfig", "bytes", json!(513)), ("usedConfig", "sha256", json!("a".repeat(64))),
            ("usedVersion", "bytes", json!(42)), ("usedVersion", "sha256", json!("a".repeat(64))),
            ("usedVersion", "source", json!("release/other.properties")), ("usedVersion", "name", json!("1.2.4")),
            ("usedVersion", "build", json!(43))] {
            let mut value = good.clone(); value["result"][container][field] = changed; assert!(parse_terminal(&value).is_err());
        }
        for field in ["module", "variant", "applicationId", "task"] {
            let mut value = good.clone(); value["result"]["selection"][field] = json!("different"); assert!(parse_terminal(&value).is_err());
        }
        let mut value = good; value["context"]["baselineGeneration"] = json!(4); assert!(parse_terminal(&value).is_err());
    }

    #[test]
    fn every_original_close_and_ledger_fact_vetoes_core_complete() {
        for field in ["complete", "contained", "inputClosed", "handlersRestored", "invocationClosed", "artifactsClosed", "toolsClosed", "namespaceClosed"] {
            let mut value = complete(); value["lifetime"][field] = json!(false); assert!(parse_terminal(&value).is_err());
            value["outcome"] = json!("unknown"); value["reason"] = json!("cleanup-unknown"); value["result"] = Value::Null;
            value["disposition"]["artifacts"] = json!("retained-incomplete");
            assert!(!parse_terminal(&value).unwrap().settled());
        }
        for (field, bad) in [("fatal", json!(true)), ("commands", json!(3)), ("profileCalls", json!(1)),
            ("commandDispatched", Value::Null), ("commandDispatched", json!(false)), ("stopObserved", json!("cancelled"))] {
            let mut value = complete(); value["lifetime"][field] = bad; assert!(parse_terminal(&value).is_err());
        }
        let mut value = complete(); value["lifetime"]["commands"] = json!(1);
        assert!(parse_terminal(&value).is_err()); // Native-manifest PASS needs actual second command.
        set_rows(&mut value, &[("aab-structure", "PASS"), ("aab-manifest", "SKIP"), ("signer", "SKIP")], "passed", "not-checked");
        assert!(parse_terminal(&value).is_ok()); // No invented bundletool call or native identity assurance.
    }

    #[test]
    fn command_failure_refusal_and_unknown_preserve_actual_known_outcomes() {
        assert!(parse_terminal(&failed(7)).unwrap().settled());
        assert!(parse_terminal(&failed(-9)).is_ok());
        assert!(parse_terminal(&failed(0)).is_err());
        assert!(parse_terminal(&refused()).unwrap().settled());
        assert!(!parse_terminal(&unknown()).unwrap().settled());
        let mut value = failed(7); value["activity"]["command"]["exitCode"] = Value::Null;
        assert!(parse_terminal(&value).is_err());
        let mut value = unknown(); value["activity"]["command"]["exitCode"] = json!(7);
        assert!(parse_terminal(&value).is_err());
        let mut value = failed(7); value["reason"] = json!("command-incomplete"); assert!(parse_terminal(&value).is_err());
        value["activity"]["command"] = json!({"outcome":"unknown","exitCode":null});
        assert!(parse_terminal(&value).is_ok()); // Settled lifetime, no inferred command return.
        let mut value = failed(7); value["outcome"] = json!("refused"); assert!(parse_terminal(&value).is_err());
    }

    #[test]
    fn capture_reasons_require_original_zero_return_and_reached_capture_stage() {
        for reason in ["artifact-missing", "artifact-ambiguous", "artifact-unsafe", "artifact-changed"] {
            let mut value = failed(0); value["reason"] = json!(reason); value["activity"]["stage"] = json!("capturing");
            assert!(parse_terminal(&value).is_ok());
            let mut bad = value.clone(); bad["activity"]["command"]["exitCode"] = json!(7); assert!(parse_terminal(&bad).is_err());
            let mut bad = value.clone(); bad["activity"]["stage"] = json!("building"); assert!(parse_terminal(&bad).is_err());
            let mut bad = value.clone(); bad["activity"]["selection"] = Value::Null; assert!(parse_terminal(&bad).is_err());
            let mut bad = value; bad["outcome"] = json!("refused"); assert!(parse_terminal(&bad).is_err());
        }
    }

    #[test]
    fn known_retained_work_is_failed_even_after_stop_not_cancelled_clean_or_unknown() {
        let mut value = failed(7); value["disposition"]["work"] = json!("retained-work");
        assert!(parse_terminal(&value).unwrap().settled());
        value["lifetime"]["stopObserved"] = json!("cancelled");
        assert_eq!(parse_terminal(&value).unwrap().reason, Reason::CommandFailed); // Earlier primary survives later stop.
        value["reason"] = json!("cancelled"); assert!(parse_terminal(&value).is_ok());
        value["outcome"] = json!("cancelled"); assert!(parse_terminal(&value).is_err());
        value["outcome"] = json!("failed"); value["reason"] = json!("timed-out"); value["lifetime"]["stopObserved"] = json!("timed-out");
        assert!(parse_terminal(&value).is_ok());
        value["outcome"] = json!("timed-out"); assert!(parse_terminal(&value).is_err());
        value["outcome"] = json!("failed"); value["reason"] = json!("work-retained"); assert!(parse_terminal(&value).is_ok());
        value["disposition"]["work"] = json!("removed"); assert!(parse_terminal(&value).is_err());
        let mut value = unknown(); value["disposition"]["work"] = json!("retained-work");
        assert!(!parse_terminal(&value).unwrap().settled());
    }

    #[test]
    fn stop_reasons_require_observed_stop_and_unknown_disposition_vetoes_settlement() {
        for (outcome, reason, stop) in [("cancelled", "cancelled", "cancelled"), ("timed-out", "timed-out", "timed-out"),
            ("failed", "context-changed", "cancelled"), ("failed", "document-lost", "cancelled"), ("failed", "shutdown", "cancelled")] {
            let mut value = failed(7); value["outcome"] = json!(outcome); value["reason"] = json!(reason);
            assert!(parse_terminal(&value).is_err());
            value["lifetime"]["stopObserved"] = json!(stop); assert!(parse_terminal(&value).is_ok());
        }
        let mut value = complete(); value["disposition"]["work"] = json!("unknown"); assert!(parse_terminal(&value).is_err());
        value["outcome"] = json!("unknown"); value["reason"] = json!("cleanup-unknown"); value["result"] = Value::Null;
        value["disposition"]["artifacts"] = json!("retained-incomplete");
        let decoded = parse_terminal(&value).unwrap();
        assert!(decoded.lifetime.settled()); assert!(!decoded.settled()); // Unknown disposition is an independent veto.
        value["disposition"]["work"] = json!("removed"); assert!(parse_terminal(&value).is_err());
    }

    #[test]
    fn failed_inspection_can_complete_without_promoting_native_or_signer_assurance() {
        let mut value = complete();
        set_rows(&mut value, &[("aab-structure", "FAIL"), ("aab-manifest", "SKIP"), ("signer", "SKIP")], "failed", "not-checked");
        assert_eq!(parse_terminal(&value).unwrap().outcome, Outcome::Complete);
        let mut wrong = value.clone(); wrong["result"]["assurances"]["structure"] = json!("passed"); assert!(parse_terminal(&wrong).is_err());
        value["lifetime"]["commands"] = json!(1); assert!(parse_terminal(&value).is_ok());
        let mut value = complete();
        set_rows(&mut value, &[("aab-structure", "PASS"), ("application-id", "PASS"), ("version-name", "PASS"),
            ("build-number", "PASS"), ("release-flags", "PASS")], "passed", "not-checked");
        assert!(parse_terminal(&value).is_ok()); // Separate findings are not the one native manifest success row.
        let mut value = complete();
        set_rows(&mut value, &[("aab-structure", "PASS"), ("aab-manifest", "PASS"), ("other-core-finding", "SKIP")], "passed", "not-checked");
        assert!(parse_terminal(&value).is_ok());
        let mut value = complete();
        set_rows(&mut value, &[("aab-structure", "PASS"), ("aab-structure", "PASS"), ("aab-manifest", "PASS")], "not-checked", "not-checked");
        assert!(parse_terminal(&value).is_ok());
        let mut value = complete();
        set_rows(&mut value, &[("aab-structure", "PASS"), ("aab-manifest", "FAIL"), ("signer", "SKIP")], "passed", "failed");
        assert!(parse_terminal(&value).is_ok());
    }

    #[test]
    fn artifacts_findings_limits_and_public_assurances_are_not_extensible() {
        for (field, bad) in [("logicalName", json!("mapping")), ("platform", json!("ios")), ("kind", json!("apk")),
            ("fileName", json!("../PRIVATE.aab")), ("size", json!(0)), ("size", json!(AAB_LIMIT + 1)),
            ("sha256", json!("F".repeat(64))), ("freshness", json!("fresh")), ("unknownAbi", json!(1)),
            ("architectures", json!(["x86", "arm64-v8a"])), ("architectures", json!(["x86", "x86"])),
            ("architectures", json!(["PRIVATE_ABI"]))] {
            let mut value = complete(); value["result"]["artifacts"][0][field] = bad; assert!(parse_terminal(&value).is_err());
        }
        let mut value = complete(); let extra = value["result"]["artifacts"][0].clone();
        value["result"]["artifacts"].as_array_mut().unwrap().push(extra); assert!(parse_terminal(&value).is_err());
        for field in ["signer", "toolkitSigning", "storeOperation", "sourceBinding", "releaseReadiness", "applicationVersion"] {
            let mut value = complete(); value["result"]["assurances"][field] = json!("verified"); assert!(parse_terminal(&value).is_err());
        }
        let mut value = complete();
        set_rows(&mut value, &[("aab-structure", "PASS"), ("aab-manifest", "PASS"), ("signer", "PASS")], "passed", "passed");
        assert!(parse_terminal(&value).is_err());
        let mut value = complete();
        set_rows(&mut value, &[("aab-structure", "PASS"), ("core-lifecycle", "SKIP")], "passed", "not-checked");
        assert!(parse_terminal(&value).is_err());
        let mut many = vec![("other-core-finding", "SKIP"); MAX_FINDINGS]; many[0] = ("aab-structure", "PASS");
        let mut value = complete(); set_rows(&mut value, &many, "passed", "not-checked"); assert!(parse_terminal(&value).is_ok());
        many.push(("aab-manifest", "FAIL")); set_rows(&mut value, &many, "passed", "failed"); assert!(parse_terminal(&value).is_err());
        let mut value = complete(); value["result"]["limitations"].as_array_mut().unwrap().reverse(); assert!(parse_terminal(&value).is_err());
    }

    #[test]
    fn required_nullable_fields_exact_counts_and_unknown_private_keys_are_rejected() {
        for field in ["result", "activity", "disposition", "lifetime"] {
            let mut value = complete(); value.as_object_mut().unwrap().remove(field); assert!(parse_terminal(&value).is_err());
        }
        for (parent, field) in [("activity", "selection"), ("lifetime", "commandDispatched")] {
            let mut value = complete(); value[parent].as_object_mut().unwrap().remove(field); assert!(parse_terminal(&value).is_err());
        }
        let mut value = refused(); value["activity"]["command"].as_object_mut().unwrap().remove("exitCode");
        assert!(parse_terminal(&value).is_err());
        for (parent, field) in [("activity", "stdout"), ("lifetime", "exception"), ("result", "argv"), ("disposition", "root")] {
            let mut value = complete(); value[parent][field] = json!("PRIVATE_SECRET");
            let error = parse_terminal(&value).unwrap_err(); assert_eq!(error, protocol_error());
            assert!(!error.to_string().contains("PRIVATE_SECRET"));
        }
        let mut value = complete(); value["activity"]["findings"][0]["message"] = json!("PRIVATE_MESSAGE");
        assert!(parse_terminal(&value).is_err());
        let mut value = complete(); value["activity"]["findings"][0]["ordinal"] = json!(1); assert!(parse_terminal(&value).is_err());
        let mut value = complete(); value["activity"]["summary"]["counts"]["PASS"] = json!(1); assert!(parse_terminal(&value).is_err());
        let mut value = complete(); value["activity"]["summary"]["omitted"] = json!(1); assert!(parse_terminal(&value).is_err());
    }

    #[test]
    fn stream_is_contiguous_monotone_optional_and_terminal_is_not_native_finality() {
        let mut stream = decoder(); assert!(matches!(stream.push(&accepted()).unwrap(), Frame::Accepted));
        assert!(matches!(stream.push(&frame(1, "terminal", complete())).unwrap(), Frame::Terminal(_)));
        assert!(stream.finish().is_ok()); assert!(stream.settled()); assert_eq!(stream.frames(), 2);
        let mut stream = decoder(); stream.push(&accepted()).unwrap();
        for (index, stage) in ["inputs-bound", "building", "capturing", "inspecting", "disposing-work"].iter().enumerate() {
            assert!(matches!(stream.push(&progress(index as u32 + 1, stage)).unwrap(), Frame::Progress(_)));
        }
        stream.push(&frame(6, "terminal", complete())).unwrap(); assert!(stream.finish().is_ok()); assert_eq!(stream.frames(), 7);
        assert!(stream.push(&frame(7, "terminal", complete())).is_err()); assert!(!stream.settled());
        let mut stream = decoder(); stream.push(&accepted()).unwrap();
        stream.push(&progress(1, "inspecting")).unwrap(); // Intermediate stages may be omitted.
        stream.push(&frame(2, "terminal", complete())).unwrap(); assert!(stream.finish().is_ok());
    }

    #[test]
    fn failed_stream_step_identity_change_or_eof_cannot_rearm_original_decoder() {
        for bad in [progress(0, "building"), frame(0, "terminal", complete()), frame(1, "accepted", json!({"schemaVersion":1,"context":context()}))] {
            let mut stream = decoder(); assert!(stream.push(&bad).is_err()); assert!(stream.push(&accepted()).is_err());
        }
        for bad in [progress(2, "building"), progress(1, "accepted"), accepted()] {
            let mut stream = decoder(); stream.push(&accepted()).unwrap(); assert!(stream.push(&bad).is_err());
            assert!(stream.push(&progress(1, "building")).is_err()); assert!(stream.finish().is_err());
        }
        for stage in ["building", "inputs-bound"] {
            let mut stream = decoder(); stream.push(&accepted()).unwrap(); stream.push(&progress(1, "building")).unwrap();
            assert!(stream.push(&progress(2, stage)).is_err());
        }
        let mut stream = decoder(); stream.push(&accepted()).unwrap(); stream.push(&progress(1, "inspecting")).unwrap();
        let mut earlier = failed(7); earlier["activity"]["stage"] = json!("building");
        assert!(stream.push(&frame(2, "terminal", earlier)).is_err());
        let mut stream = decoder(); stream.push(&accepted()).unwrap(); assert!(stream.finish().is_err());
        assert!(stream.push(&frame(1, "terminal", complete())).is_err());
        for (field, bad) in [("protocol", json!("mrk-offline-preflight/1")), ("operationId", json!("c".repeat(32))),
            ("ownerGeneration", json!("d".repeat(32)))] {
            let mut value: Value = serde_json::from_slice(&accepted()).unwrap(); value[field] = bad;
            let mut bytes = serde_json::to_vec(&value).unwrap(); bytes.push(b'\n');
            let mut stream = decoder(); assert!(stream.push(&bytes).is_err());
        }
        let mut value = complete(); value["context"]["savedVersion"]["name"] = json!("1.2.4");
        let mut stream = decoder(); stream.push(&accepted()).unwrap(); assert!(stream.push(&frame(1, "terminal", value)).is_err());
    }

    #[test]
    fn frame_framing_duplicate_keys_and_aggregate_budget_veto_positive_terminal() {
        let first = accepted(); let last = frame(1, "terminal", complete());
        let mut padded = vec![b' '; RESPONSE_LIMIT - first.len() - last.len()]; padded.extend_from_slice(&first);
        let mut stream = decoder(); stream.push(&padded).unwrap(); stream.push(&last).unwrap();
        assert_eq!(stream.bytes(), RESPONSE_LIMIT); assert!(stream.finish().is_ok());
        padded.insert(0, b' ');
        let mut stream = decoder(); stream.push(&padded).unwrap(); assert!(stream.push(&last).is_err()); assert!(!stream.settled());
        let mut missing_newline = first.clone(); missing_newline.pop();
        let mut extra_newline = first.clone(); extra_newline.push(b'\n');
        let duplicate = String::from_utf8(first.clone()).unwrap().replacen("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1", 1).into_bytes();
        for bytes in [missing_newline, extra_newline, duplicate] {
            let mut stream = decoder(); assert!(stream.push(&bytes).is_err()); assert!(stream.push(&first).is_err());
        }
        let mut stream = decoder(); stream.frames = MAX_FRAMES; assert!(stream.push(&last).is_err());
    }

    #[test]
    fn native_status_hides_provisional_core_activity_artifacts_and_unknown_results() {
        let good = native_complete();
        let typed = status(&good).unwrap(); let bytes = status_bytes(&typed).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), good);
        for private in ["PRIVATE_PROJECT", "PRIVATE_TOOLS", "PRIVATE_CWD", "inventorySha256", "lifetime", "stdout", "argv"] {
            assert!(!String::from_utf8(bytes.clone()).unwrap().contains(private));
        }
        for phase in ["starting", "running", "stopping", "unknown"] {
            let mut value = good.clone(); value["operation"]["phase"] = json!(phase); assert!(status(&value).is_err());
        }
        let mut pending = good.clone(); pending["operation"]["phase"] = json!("running");
        pending["operation"]["outcome"] = Value::Null; pending["operation"]["activity"] = Value::Null;
        pending["operation"]["disposition"] = Value::Null; pending["operation"]["result"] = Value::Null;
        assert!(status(&pending).is_ok()); // Reached stage, not a current completed result.
        pending["operation"]["phase"] = json!("starting"); assert!(status(&pending).is_err());
        pending["operation"]["stage"] = Value::Null; assert!(status(&pending).is_ok());
        pending["operation"]["phase"] = json!("awaiting-consent"); pending["operation"]["intentUsable"] = json!(true);
        assert!(status(&pending).is_ok()); pending["operation"]["intentUsable"] = json!(false); assert!(status(&pending).is_ok());
        pending["operation"]["phase"] = json!("unknown"); pending["operation"]["outcome"] = json!("unknown");
        pending["operation"]["reason"] = json!("cleanup-unknown"); pending["operation"]["stage"] = json!("building");
        pending["availability"] = json!("cleanup-unknown"); assert!(status(&pending).is_ok());
        pending["operation"]["activity"] = good["operation"]["activity"].clone(); assert!(status(&pending).is_err());
    }

    #[test]
    fn native_status_preserves_negative_work_facts_without_a_core_or_native_receipt() {
        let mut value = native_complete(); let core = failed(7);
        value["operation"]["outcome"] = json!("failed"); value["operation"]["reason"] = json!("command-failed");
        value["operation"]["result"] = Value::Null; value["operation"]["activity"] = core["activity"].clone();
        value["operation"]["disposition"] = core["disposition"].clone();
        value["operation"]["disposition"]["work"] = json!("retained-work"); assert!(status(&value).is_ok());
        value["operation"]["reason"] = json!("cancelled"); assert!(status(&value).is_ok());
        value["operation"]["outcome"] = json!("cancelled"); assert!(status(&value).is_err());
        value["operation"]["outcome"] = json!("failed"); value["operation"]["reason"] = json!("protocol-error");
        value["operation"]["activity"] = Value::Null; value["operation"]["disposition"] = Value::Null;
        assert!(status(&value).is_ok()); // Original native failure after progress, no invented command facts.
        for reason in ["command-failed", "command-incomplete", "artifact-missing", "artifact-ambiguous", "artifact-unsafe", "artifact-changed", "work-retained"] {
            value["operation"]["reason"] = json!(reason); assert!(status(&value).is_err());
        }
    }

    #[test]
    fn native_retirement_preserves_first_cancellation_reason_without_inventing_core_facts() {
        for reason in ["cancelled", "context-changed", "document-lost", "shutdown"] {
            let mut value = native_complete();
            value["operation"]["outcome"] = json!("cancelled"); value["operation"]["reason"] = json!(reason);
            value["operation"]["stage"] = Value::Null; value["operation"]["activity"] = Value::Null;
            value["operation"]["disposition"] = Value::Null; value["operation"]["result"] = Value::Null;
            assert!(status(&value).is_ok()); // Original prepared intent retired, no core command/cleanup claim.
            value["operation"]["stage"] = json!("building");
            assert!(status(&value).is_ok()); // Reached stage still is not checked core activity.
            let mut core = failed(7);
            core["outcome"] = json!("cancelled"); core["reason"] = json!(reason);
            core["lifetime"]["stopObserved"] = json!("cancelled");
            assert_eq!(parse_terminal(&core).is_ok(), reason == "cancelled"); // Python/Core stays strict.
            value["operation"]["stage"] = core["activity"]["stage"].clone();
            value["operation"]["activity"] = core["activity"].clone();
            value["operation"]["disposition"] = core["disposition"].clone();
            assert!(status(&value).is_ok());
            value["operation"]["disposition"]["work"] = json!("retained-work");
            assert!(status(&value).is_err()); // A cancellation reason cannot hide known retained work.
        }
        for reason in ["protocol-error", "timed-out", "runtime-unavailable", "cleanup-unknown"] {
            let mut value = native_complete(); value["operation"]["outcome"] = json!("cancelled");
            value["operation"]["reason"] = json!(reason); value["operation"]["activity"] = Value::Null;
            value["operation"]["disposition"] = Value::Null; value["operation"]["result"] = Value::Null;
            assert!(status(&value).is_err());
        }
    }

    #[test]
    fn native_status_required_nullables_counters_and_closed_availability_fail_cleanly() {
        let good = native_complete();
        for field in ["outcome", "stage", "activity", "disposition", "result"] {
            let mut bad = good.clone(); bad["operation"].as_object_mut().unwrap().remove(field); assert!(status(&bad).is_err());
        }
        for revision in [json!(u32::MAX), json!(-1), json!(true), json!(7.0)] {
            let mut bad = good.clone(); bad["statusRevision"] = revision; assert!(status(&bad).is_err());
        }
        let unavailable = json!({"schemaVersion":1,"statusRevision":0,"availability":"toolchain-unqualified","operation":null});
        assert!(status(&unavailable).is_ok()); // DATA availability, no code enables that profile.
        let mut bad = unavailable.clone(); bad["qualified"] = json!(true); assert!(status(&bad).is_err());
        let mut bad = unavailable; bad["availability"] = json!("qualified"); assert!(status(&bad).is_err());
        let mut bad = good; bad["operation"]["result"]["usedVersion"]["build"] = json!(43); assert!(status(&bad).is_err());
    }
}
