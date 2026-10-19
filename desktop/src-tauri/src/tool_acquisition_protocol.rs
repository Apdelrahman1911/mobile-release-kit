//! Closed tool-preparation DATA. Only the original saved owner can retain a
//! joined inspection or lend cache/runtime/catalogue originals; these DTOs cannot.
use crate::{
    asset_source::RegisteredRoot,
    edit_protocol::{bounded, token},
    error::BridgeError,
    protocol::{strict_json, valid_id},
    tool_preparation as plan,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{self, Write},
    path::Path,
};

pub(crate) const PROTOCOL: &str = "mrk-tool-acquisition/1";
pub(crate) const CONSENT: &str = "pinned-public-tool-sources-v1";
pub(crate) const EVENT: &str = "tool-acquisition-state-changed";
pub(crate) const IPC_LIMIT: usize = 8192;
pub(crate) const REQUEST_LIMIT: usize = 12 * 1024 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024;
pub(crate) const STATUS_LIMIT: usize = 64 * 1024;
pub(crate) const CONTROL_LIMIT: usize = 16 * 1024;
pub(crate) const CA_LIMIT: usize = 512 * 1024;
pub(crate) const MANIFEST_LIMIT: usize = 8 * 1024 * 1024;
pub(crate) const COMPONENTS: [&str; 4] = ["jdk", "sdk-platform", "sdk-build-tools", "gradle"];
pub(crate) const FIXED: [&str; 7] = [
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "gradle.properties",
    "gradle/libs.versions.toml",
    "gradle/wrapper/gradle-wrapper.properties",
];
pub(crate) const CONFIG: &str = "release/mobile-release.json";

/// Fixed canonical field order, independent of serde_json's preserve_order
/// feature. The child compares these exact bytes before any cache publication.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IntentData<'a> {
    cache_generation: u32,
    components: [&'static str; 4],
    context_sha256: &'a str,
    operation_id: &'a str,
    profile: Profile,
    projection_sha256: &'a str,
    reference_sha256: &'a str,
    schema_version: u32,
}
pub(crate) fn intent_bytes(
    operation: &str,
    generation: u32,
    profile: Profile,
    context: &str,
    reference: &str,
    projection: &str,
) -> Result<Vec<u8>, BridgeError> {
    if !token(operation)
        || generation == 0
        || ![context, reference, projection].into_iter().all(sha)
    {
        return Err(invalid());
    }
    bounded(
        &IntentData {
            cache_generation: generation,
            components: COMPONENTS,
            context_sha256: context,
            operation_id: operation,
            profile,
            projection_sha256: projection,
            reference_sha256: reference,
            schema_version: 1,
        },
        CONTROL_LIMIT,
    )
}
pub(crate) fn invalid() -> BridgeError {
    BridgeError::new(
        "tool_acquisition_invalid",
        "Check this project's build tools again before downloading missing tools.",
    )
}
pub(crate) fn keys(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|map| {
        map.len() == names.len() && names.iter().all(|name| map.contains_key(*name))
    })
}
pub(crate) fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
pub(crate) fn raw_request(raw: &[u8]) -> Result<Value, BridgeError> {
    if !(1..=IPC_LIMIT).contains(&raw.len()) {
        return Err(invalid());
    }
    strict_json(raw).map_err(|_| invalid())
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Content {
    pub(crate) bytes: u32,
    pub(crate) sha256: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Action {
    Inspect,
    Acquire,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) operation_id: String,
    pub(crate) owner_generation: String,
    pub(crate) requirements_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) project_id: String,
    pub(crate) draft_revision: u32,
    pub(crate) baseline_generation: u32,
    pub(crate) saved_config: Content,
    pub(crate) action: Action,
    #[serde(deserialize_with = "present")]
    pub(crate) review: Option<Review>,
}
impl Context {
    pub(crate) fn valid(&self) -> bool {
        valid_id(&self.project_id)
            && self.draft_revision < u32::MAX
            && self.baseline_generation < u32::MAX
            && (1..=524288).contains(&self.saved_config.bytes)
            && sha(&self.saved_config.sha256)
            && match (self.action, &self.review) {
                (Action::Inspect, None) => true,
                (Action::Acquire, Some(r)) => {
                    token(&r.operation_id)
                        && token(&r.owner_generation)
                        && sha(&r.requirements_sha256)
                }
                _ => false,
            }
    }
    pub(crate) fn same_saved(&self, other: &Self) -> bool {
        self.project_id == other.project_id
            && self.draft_revision == other.draft_revision
            && self.baseline_generation == other.baseline_generation
            && self.saved_config == other.saved_config
    }
}
pub(crate) type Prepare = Context;
impl Prepare {
    pub(crate) fn context(&self) -> Context {
        self.clone()
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Start {
    pub(crate) operation_id: String,
    pub(crate) owner_generation: String,
    consent_version: String,
}
impl Start {
    pub(crate) fn consents(&self) -> bool {
        token(&self.operation_id)
            && token(&self.owner_generation)
            && self.consent_version == CONSENT
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Cancel {
    pub(crate) operation_id: String,
    pub(crate) owner_generation: String,
}
pub(crate) fn prepare(value: &Value) -> Result<Prepare, BridgeError> {
    let input = Prepare::deserialize(value).map_err(|_| invalid())?;
    if !input.valid() {
        return Err(invalid());
    }
    Ok(input)
}
pub(crate) fn start(value: &Value) -> Result<Start, BridgeError> {
    let input = Start::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id)
        || !token(&input.owner_generation)
        || input.consent_version != CONSENT
    {
        return Err(invalid());
    }
    Ok(input)
}
pub(crate) fn cancel(value: &Value) -> Result<Cancel, BridgeError> {
    let input = Cancel::deserialize(value).map_err(|_| invalid())?;
    if !token(&input.operation_id) || !token(&input.owner_generation) {
        return Err(invalid());
    }
    Ok(input)
}
pub(crate) fn status_request(value: &Value) -> Result<(), BridgeError> {
    if keys(value, &[]) {
        Ok(())
    } else {
        Err(invalid())
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Profile {
    #[serde(rename = "macos-arm64")]
    MacArm64,
    #[serde(rename = "macos-x86_64")]
    MacX64,
}
impl Profile {
    pub(crate) fn current() -> Option<Self> {
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            Some(Self::MacArm64)
        } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            Some(Self::MacX64)
        } else {
            None
        }
    }
    pub(crate) fn android(self) -> crate::android_build_protocol::Profile {
        match self {
            Self::MacArm64 => crate::android_build_protocol::Profile::MacArm64,
            Self::MacX64 => crate::android_build_protocol::Profile::MacX64,
        }
    }
}
pub(crate) fn native_path(path: &Path) -> Option<&str> {
    let text = path.to_str()?;
    if !text.starts_with('/')
        || text.len() > 4096
        || text.bytes().any(|b| b < 32 || b == 127 || b == b'\\')
    {
        return None;
    }
    if text != "/" {
        let parts: Vec<_> = text[1..].split('/').collect();
        if parts.len() > 128
            || parts
                .iter()
                .any(|part| part.is_empty() || matches!(*part, "." | "..") || part.len() > 255)
        {
            return None;
        }
    }
    Some(text)
}
struct RequestWriter(Vec<u8>);
impl Write for RequestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n >= REQUEST_LIMIT)
        {
            return Err(io::Error::other("fixed tool request limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(crate) fn request(
    operation: &str,
    generation: &str,
    context: &Context,
    profile: Profile,
    project: &RegisteredRoot,
    cwd: &Path,
    cache: Option<&Value>,
    manifest: Option<&[u8]>,
    ca: Option<&[u8]>,
) -> Result<Vec<u8>, BridgeError> {
    if !token(operation)
        || !token(generation)
        || !context.valid()
        || match context.action {
            Action::Inspect => cache.is_some() || manifest.is_some() || ca.is_some(),
            Action::Acquire => {
                cache.is_none()
                    || manifest.is_none_or(|b| b.is_empty() || b.len() > MANIFEST_LIMIT)
                    || ca.is_none_or(|b| b.is_empty() || b.len() > CA_LIMIT)
            }
        }
    {
        return Err(invalid());
    }
    let identity = project
        .identity
        .posix()
        .map_err(|_| invalid())?
        .preflight_identity();
    let value = json!({"protocol":PROTOCOL,"operationId":operation,"ownerGeneration":generation,"context":context,
        "native":{"profile":profile,"projectRoot":native_path(&project.path).ok_or_else(invalid)?,"rootIdentity":identity,
            "cwd":native_path(cwd).ok_or_else(invalid)?,"cache":cache,
            "manifestBase64":manifest.map(|b|STANDARD.encode(b)),"caBase64":ca.map(|b|STANDARD.encode(b))}});
    // Charge the actual fixed capacity, not only encoded length: the general
    // edit writer may otherwise geometrically grow beyond this domain's cap.
    let mut writer = RequestWriter(Vec::new());
    writer
        .0
        .try_reserve_exact(REQUEST_LIMIT)
        .map_err(|_| invalid())?;
    if writer.0.capacity() > REQUEST_LIMIT {
        return Err(invalid());
    }
    serde_json::to_writer(&mut writer, &value).map_err(|_| invalid())?;
    writer.0.push(b'\n');
    Ok(writer.0)
}

/// The same fixed grammar is checked before *any* native relative-path IO.
pub(crate) fn module_files(module: &str) -> Option<[String; 2]> {
    let tail = module.strip_prefix(':')?;
    let parts: Vec<_> = if tail.is_empty() {
        vec![]
    } else {
        tail.split(':').collect()
    };
    if parts.len() > 12
        || parts.iter().any(|s| {
            s.is_empty()
                || s.len() > 64
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
    {
        return None;
    }
    let mut prefix = parts.join("/");
    if !prefix.is_empty() {
        prefix.push('/');
    }
    if prefix.len() + "build.gradle.kts".len() > 256 {
        return None;
    }
    Some([
        format!("{prefix}build.gradle"),
        format!("{prefix}build.gradle.kts"),
    ])
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryIdentity {
    pub(crate) device: String,
    pub(crate) inode: String,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}
impl DirectoryIdentity {
    pub(crate) fn valid(&self) -> bool {
        [self.device.as_str(), self.inode.as_str()]
            .into_iter()
            .all(decimal)
            && self.inode != "0"
            && self.mode & 0o170000 == 0o040000
    }
}
fn decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u64>().is_ok()
}
fn nanos(value: &str) -> bool {
    let raw = value.strip_prefix('-').unwrap_or(value);
    decimal(raw) && value.parse::<i128>().is_ok()
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FileIdentity {
    pub(crate) device: String,
    pub(crate) inode: String,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) links: u32,
    pub(crate) bytes: u32,
    pub(crate) mtime_ns: String,
    pub(crate) ctime_ns: String,
}
impl FileIdentity {
    fn valid(&self) -> bool {
        decimal(&self.device)
            && decimal(&self.inode)
            && self.inode != "0"
            && self.mode & 0o170000 == 0o100000
            && self.links > 0
            && self.bytes <= 524288
            && nanos(&self.mtime_ns)
            && nanos(&self.ctime_ns)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Directory {
    pub(crate) relative: String,
    pub(crate) identity: DirectoryIdentity,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct File {
    pub(crate) relative: String,
    pub(crate) identity: FileIdentity,
    pub(crate) sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Footprint {
    pub(crate) module: String,
    pub(crate) build_file: String,
    pub(crate) sources_sha256: String,
    pub(crate) directories: Vec<Directory>,
    pub(crate) missing: Vec<String>,
    pub(crate) files: Vec<File>,
}
impl Footprint {
    pub(crate) fn valid(&self) -> bool {
        let Some(candidates) = module_files(&self.module) else {
            return false;
        };
        if !candidates.contains(&self.build_file)
            || !sha(&self.sources_sha256)
            || self.directories.len() > 132
            || self.missing.len() > 9
            || !(1..=10).contains(&self.files.len())
        {
            return false;
        }
        let names: BTreeSet<&str> = FIXED
            .into_iter()
            .chain([CONFIG])
            .chain(candidates.iter().map(String::as_str))
            .collect();
        let prefixes: BTreeSet<String> = names
            .iter()
            .flat_map(|name| {
                let parts: Vec<_> = name.split('/').collect();
                (1..parts.len()).map(move |n| parts[..n].join("/"))
            })
            .collect();
        let dirs: Vec<&str> = self
            .directories
            .iter()
            .map(|r| r.relative.as_str())
            .collect();
        let files: Vec<&str> = self.files.iter().map(|r| r.relative.as_str()).collect();
        let missing: Vec<&str> = self.missing.iter().map(String::as_str).collect();
        if self
            .directories
            .iter()
            .any(|r| !prefixes.contains(&r.relative) || !r.identity.valid())
            || self.files.iter().any(|r| {
                !names.contains(r.relative.as_str()) || !r.identity.valid() || !sha(&r.sha256)
            })
            || missing
                .iter()
                .any(|name| !names.contains(name) && !prefixes.contains(*name))
            || [&dirs, &files, &missing]
                .into_iter()
                .any(|rows| rows.windows(2).any(|w| w[0] >= w[1]))
            || !files.contains(&CONFIG)
            || self
                .files
                .iter()
                .map(|r| u64::from(r.identity.bytes))
                .sum::<u64>()
                > 5 * 524288
            || dirs
                .iter()
                .any(|d| files.contains(d) || missing.contains(d))
            || files.iter().any(|f| missing.contains(f))
        {
            return false;
        }
        for name in &names {
            let count = missing
                .iter()
                .copied()
                .filter(|m| {
                    *name == *m
                        || name
                            .strip_prefix(*m)
                            .is_some_and(|rest| rest.starts_with('/'))
                })
                .count();
            if count != usize::from(!files.contains(name)) {
                return false;
            }
        }
        dirs.iter()
            .chain(files.iter())
            .chain(missing.iter())
            .all(|name| {
                let parts: Vec<_> = name.split('/').collect();
                (1..parts.len()).all(|n| dirs.contains(&parts[..n].join("/").as_str()))
            })
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(self.module.capacity())?
            .checked_add(self.build_file.capacity())?
            .checked_add(self.sources_sha256.capacity())?
            .checked_add(
                self.directories
                    .capacity()
                    .checked_mul(std::mem::size_of::<Directory>())?,
            )?
            .checked_add(
                self.missing
                    .capacity()
                    .checked_mul(std::mem::size_of::<String>())?,
            )?
            .checked_add(
                self.files
                    .capacity()
                    .checked_mul(std::mem::size_of::<File>())?,
            )?;
        for d in &self.directories {
            bytes = bytes
                .checked_add(d.relative.capacity())?
                .checked_add(d.identity.device.capacity())?
                .checked_add(d.identity.inode.capacity())?;
        }
        for m in &self.missing {
            bytes = bytes.checked_add(m.capacity())?;
        }
        for f in &self.files {
            for s in [
                &f.relative,
                &f.sha256,
                &f.identity.device,
                &f.identity.inode,
                &f.identity.mtime_ns,
                &f.identity.ctime_ns,
            ] {
                bytes = bytes.checked_add(s.capacity())?;
            }
        }
        Some(bytes)
    }
}
pub(crate) fn footprint(value: &Value) -> Result<Footprint, BridgeError> {
    let value = Footprint::deserialize(value).map_err(|_| invalid())?;
    if !value.valid() {
        return Err(invalid());
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome {
    Complete,
    Refused,
    Cancelled,
    TimedOut,
    Failed,
    Unknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    Cancelled,
    TimedOut,
    ContextChanged,
    DocumentLost,
    Shutdown,
    RuntimeUnavailable,
    ProtocolError,
    IntentExpired,
    StaleIntent,
    CleanupUnknown,
    InputLimit,
    ResultLimit,
    Input,
    Unsupported,
    Stale,
    CensusIncomplete,
    RecoveryRequired,
    CacheConflict,
    DiskSpace,
    Network,
    Redirect,
    Framing,
    ArchiveDigest,
    ArchiveLayout,
    ArchiveMember,
    Limit,
    AlreadyUsed,
    Unknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CoreStop {
    None,
    Cancelled,
    TimedOut,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Lifetime {
    complete: bool,
    fatal: bool,
    contained: bool,
    #[serde(deserialize_with = "present")]
    command_dispatched: Option<bool>,
    commands: u32,
    profile_calls: u32,
    input_closed: bool,
    handlers_restored: bool,
    resources_closed: bool,
    stop_observed: CoreStop,
}
impl Lifetime {
    pub(crate) fn settled(&self) -> bool {
        self.complete
            && !self.fatal
            && self.contained
            && self.command_dispatched == Some(false)
            && self.commands == 0
            && self.profile_calls == 0
            && self.input_closed
            && self.handlers_restored
            && self.resources_closed
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Terminal {
    schema_version: u32,
    pub(crate) context: Context,
    pub(crate) outcome: Outcome,
    pub(crate) reason: Reason,
    #[serde(deserialize_with = "present")]
    pub(crate) result: Option<Value>,
    pub(crate) lifetime: Lifetime,
}
impl Terminal {
    fn valid(&self, operation: &str, context: &Context) -> bool {
        if self.schema_version != 1
            || &self.context != context
            || !context.valid()
            || self.lifetime.commands != 0
            || self.lifetime.profile_calls != 0
            || self.lifetime.command_dispatched == Some(true)
        {
            return false;
        }
        if self.outcome == Outcome::Complete {
            return self.reason == Reason::None
                && self.lifetime.settled()
                && self.lifetime.stop_observed == CoreStop::None
                && self
                    .result
                    .as_ref()
                    .is_some_and(|v| result_valid(v, operation, context).is_ok());
        }
        if self.result.is_some() || self.reason == Reason::None {
            return false;
        }
        if self.outcome == Outcome::Unknown {
            return self.reason == Reason::CleanupUnknown && !self.lifetime.settled();
        }
        self.lifetime.settled()
            && match self.outcome {
                Outcome::Cancelled => {
                    self.reason == Reason::Cancelled
                        && self.lifetime.stop_observed == CoreStop::Cancelled
                }
                Outcome::TimedOut => {
                    self.reason == Reason::TimedOut
                        && self.lifetime.stop_observed == CoreStop::TimedOut
                }
                Outcome::Refused | Outcome::Failed => true,
                _ => false,
            }
    }
    pub(crate) fn public_result(&self) -> Option<Value> {
        self.result.as_ref().map(|v| match self.context.action {
            Action::Inspect => {
                json!({"kind":"tool-requirements-observation","requirements":v["requirements"]})
            }
            Action::Acquire => v.clone(),
        })
    }
}
fn result_valid(v: &Value, operation: &str, context: &Context) -> Result<(), BridgeError> {
    if context.action == Action::Inspect {
        if !keys(v, &["kind", "requirements", "footprint"])
            || v["kind"] != "tool-requirements-observation"
        {
            return Err(invalid());
        }
        let fp = footprint(&v["footprint"])?;
        if !fp.files.iter().any(|row| {
            row.relative == CONFIG
                && row.identity.bytes == context.saved_config.bytes
                && row.sha256 == context.saved_config.sha256
        }) {
            return Err(invalid());
        }
        let (sha, requirements) = crate::tool_preparation_protocol::requirements(&bounded(
            &v["requirements"],
            CONTROL_LIMIT,
        )?)?;
        if sha != fp.sources_sha256
            || !requirements.complete
            || requirements.platform != plan::Platform::Android
        {
            return Err(invalid());
        }
        return Ok(());
    }
    if !keys(
        v,
        &[
            "schemaVersion",
            "kind",
            "operationId",
            "contextSha256",
            "referenceSha256",
            "projectionSha256",
            "cacheJob",
            "lookupScope",
            "reusedArchives",
            "downloadedArchives",
            "groups",
            "assurance",
        ],
    ) || v["schemaVersion"] != 1
        || v["kind"] != "staged-tool-sources"
        || v["operationId"] != operation
        || v["cacheJob"] != format!("tool-{operation}")
        || v["lookupScope"] != "registered-selected-known"
        || ["contextSha256", "referenceSha256", "projectionSha256"]
            .into_iter()
            .any(|key| !v[key].as_str().is_some_and(sha))
        || v["assurance"] != json!({"nativeFinality":false,"registered":false,"readyToBuild":false})
    {
        return Err(invalid());
    }
    let mut all = BTreeSet::new();
    for field in ["reusedArchives", "downloadedArchives"] {
        let rows = v[field].as_array().ok_or_else(invalid)?;
        let values: Vec<_> = rows
            .iter()
            .map(|row| row.as_str().ok_or_else(invalid))
            .collect::<Result<_, _>>()?;
        if values
            != COMPONENTS
                .into_iter()
                .filter(|part| values.contains(part))
                .collect::<Vec<_>>()
            || values.iter().any(|part| !all.insert(*part))
        {
            return Err(invalid());
        }
    }
    if all.len() != 4 {
        return Err(invalid());
    }
    let expected = json!([
        {"group":"jdk","components":["jdk"],"allRequiredComponentsStaged":true,"next":"choose-native-source"},
        {"group":"sdk","components":["sdk-platform","sdk-build-tools"],"allRequiredComponentsStaged":true,"next":"choose-native-source"},
        {"group":"gradle","components":["gradle"],"allRequiredComponentsStaged":true,"next":"choose-native-source"}]);
    if v["groups"] != expected {
        return Err(invalid());
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Accepted {
    schema_version: u32,
    context: Context,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    protocol: String,
    operation_id: String,
    owner_generation: String,
    sequence: u32,
    kind: String,
    payload: Value,
}
pub(crate) enum Frame {
    Accepted,
    Terminal(Terminal),
}
pub(crate) fn decode(
    bytes: &[u8],
    operation: &str,
    generation: &str,
    context: &Context,
) -> Result<Frame, BridgeError> {
    if bytes.len() < 3
        || bytes.len() > RESPONSE_LIMIT
        || !bytes.ends_with(b"\n")
        || bytes[0] != b'{'
        || bytes[bytes.len() - 2] != b'}'
        || bytes[..bytes.len() - 1]
            .iter()
            .any(|b| matches!(*b, b'\r' | b'\n'))
    {
        return Err(BridgeError::protocol());
    }
    let v = strict_json(&bytes[..bytes.len() - 1])?;
    let e = Envelope::deserialize(v).map_err(|_| BridgeError::protocol())?;
    if e.protocol != PROTOCOL
        || e.operation_id != operation
        || e.owner_generation != generation
        || !token(operation)
        || !token(generation)
    {
        return Err(BridgeError::protocol());
    }
    match (e.sequence, e.kind.as_str()) {
        (0, "accepted") => {
            let a = Accepted::deserialize(e.payload).map_err(|_| BridgeError::protocol())?;
            if a.schema_version != 1 || &a.context != context || !context.valid() {
                return Err(BridgeError::protocol());
            }
            Ok(Frame::Accepted)
        }
        (1, "terminal") => {
            let t = Terminal::deserialize(e.payload).map_err(|_| BridgeError::protocol())?;
            if !t.valid(operation, context) {
                return Err(BridgeError::protocol());
            }
            Ok(Frame::Terminal(t))
        }
        _ => Err(BridgeError::protocol()),
    }
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    AwaitingConsent,
    Starting,
    Running,
    Stopping,
    Terminal,
    Unknown,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Availability {
    Available,
    Busy,
    Shutdown,
    CleanupUnknown,
    DocumentLost,
    UnsupportedPlatform,
    RuntimeUnqualified,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Projection {
    pub(crate) operation_id: String,
    pub(crate) owner_generation: String,
    pub(crate) context: Context,
    pub(crate) phase: Phase,
    pub(crate) intent_usable: bool,
    pub(crate) outcome: Option<Outcome>,
    pub(crate) reason: Reason,
    pub(crate) result: Option<Value>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32,
    pub(crate) status_revision: u32,
    pub(crate) availability: Availability,
    pub(crate) operation: Option<Projection>,
}

#[cfg(test)]
mod tests {
    // Closed, synthetic DATA only. No native path is opened and no child runs.
    use super::*;
    fn context_value() -> Value {
        json!({"projectId":"synthetic-project","draftRevision":1,"baselineGeneration":2,
            "savedConfig":{"bytes":2,"sha256":"a".repeat(64)},"action":"inspect","review":null})
    }
    fn footprint_value() -> Value {
        json!({"module":":app","buildFile":"app/build.gradle","sourcesSha256":"b".repeat(64),
            "directories":[{"relative":"release","identity":{"device":"1","inode":"2","mode":0o40700,"uid":501,"gid":20}}],
            "missing":["app","build.gradle","build.gradle.kts","gradle","gradle.properties","settings.gradle","settings.gradle.kts"],
            "files":[{"relative":CONFIG,"identity":{"device":"1","inode":"3","mode":0o100600,"uid":501,"gid":20,
                "links":1,"bytes":2,"mtimeNs":"1","ctimeNs":"1"},"sha256":"a".repeat(64)}]})
    }
    fn requirements_value() -> Value {
        json!({"schemaVersion":1,"basis":"unverified-static-source-hints","sourcesSha256":"b".repeat(64),"complete":true,
            "platform":"android","projectCodeExecuted":false,"xcode":{"version":"26.3","build":"17C529"},
            "android":{"jdk":{"state":"literal","value":"17"},"agp":{"state":"literal","value":"8.9.2"},
                "sdkPlatform":{"state":"literal","value":"android-35"},"sdkBuildTools":{"state":"unspecified","value":null},
                "gradle":{"state":"literal","version":"8.14.5","distributionUrl":"https://services.gradle.org/distributions/gradle-8.14.5-bin.zip","sha256":"c".repeat(64)}}})
    }
    fn terminal_value() -> Value {
        json!({"schemaVersion":1,"context":context_value(),"outcome":"complete","reason":"none",
            "result":{"kind":"tool-requirements-observation","requirements":requirements_value(),"footprint":footprint_value()},
            "lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":false,"commands":0,"profileCalls":0,
                "inputClosed":true,"handlersRestored":true,"resourcesClosed":true,"stopObserved":"none"}})
    }
    fn frame(payload: Value, sequence: u32, kind: &str) -> Vec<u8> {
        let mut bytes=serde_json::to_vec(&json!({"protocol":PROTOCOL,"operationId":"d".repeat(32),"ownerGeneration":"e".repeat(32),
            "sequence":sequence,"kind":kind,"payload":payload})).unwrap();
        bytes.push(b'\n');
        bytes
    }
    fn decode_terminal(value: Value) -> Result<Frame, BridgeError> {
        decode(
            &frame(value, 1, "terminal"),
            &"d".repeat(32),
            &"e".repeat(32),
            &prepare(&context_value()).unwrap(),
        )
    }
    #[test]
    fn closed_ipc_requires_current_review_and_explicit_exact_consent() {
        assert!(prepare(&context_value()).is_ok());
        for name in [
            "native",
            "url",
            "cache",
            "sourceSnapshot",
            "argv",
            "consent",
        ] {
            let mut value = context_value();
            value[name] = json!({});
            assert!(prepare(&value).is_err());
        }
        let mut value = context_value();
        value.as_object_mut().unwrap().remove("review");
        assert!(prepare(&value).is_err());
        let mut value = context_value();
        value["action"] = json!("acquire");
        assert!(prepare(&value).is_err());
        value["review"] = json!({"operationId":"d".repeat(32),"ownerGeneration":"e".repeat(32),"requirementsSha256":"b".repeat(64)});
        assert!(prepare(&value).is_ok());
        assert!(start(&json!({"operationId":"d".repeat(32),"ownerGeneration":"e".repeat(32),"consentVersion":CONSENT})).is_ok());
        for consent in ["", "tool-preparation", "pinned-public-tool-sources-v2"] {
            assert!(start(&json!({"operationId":"d".repeat(32),"ownerGeneration":"e".repeat(32),"consentVersion":consent})).is_err());
        }
        assert!(raw_request(br#"{"projectId":"a","projectId":"b"}"#).is_err());
        assert!(status_request(&json!({"nativeFinality":true})).is_err());
    }
    #[test]
    fn pending_intent_is_canonical_independently_of_json_map_feature_order() {
        let operation = "a".repeat(32);
        let context = "b".repeat(64);
        let reference = "c".repeat(64);
        let projection = "d".repeat(64);
        let raw = intent_bytes(
            &operation,
            7,
            Profile::MacArm64,
            &context,
            &reference,
            &projection,
        )
        .unwrap();
        let expected=format!("{{\"cacheGeneration\":7,\"components\":[\"jdk\",\"sdk-platform\",\"sdk-build-tools\",\"gradle\"],\"contextSha256\":\"{context}\",\"operationId\":\"{operation}\",\"profile\":\"macos-arm64\",\"projectionSha256\":\"{projection}\",\"referenceSha256\":\"{reference}\",\"schemaVersion\":1}}");
        assert_eq!(raw, expected.as_bytes());
        assert!(intent_bytes(
            &operation,
            0,
            Profile::MacArm64,
            &context,
            &reference,
            &projection
        )
        .is_err());
    }
    #[test]
    fn fixed_module_and_full_negative_footprint_refuse_dot_traversal() {
        assert_eq!(
            module_files(":"),
            Some(["build.gradle".into(), "build.gradle.kts".into()])
        );
        assert_eq!(
            module_files(":app:release"),
            Some([
                "app/release/build.gradle".into(),
                "app/release/build.gradle.kts".into()
            ])
        );
        for bad in [
            ":.", ":..", ":a:..", ":a/b", ":a::b", ":a.b", ":a\\b", "app",
        ] {
            assert!(module_files(bad).is_none());
        }
        assert!(footprint(&footprint_value()).is_ok());
        for (field, replacement) in [
            ("module", json!(":..")),
            ("buildFile", json!("elsewhere/build.gradle")),
            ("missing", json!([])),
            ("directories", json!([])),
        ] {
            let mut value = footprint_value();
            value[field] = replacement;
            assert!(footprint(&value).is_err());
        }
        let mut value = footprint_value();
        value["files"][0]["identity"]["mode"] = json!(0o120777);
        assert!(footprint(&value).is_err());
        assert!(native_path(Path::new("/synthetic/a/../b")).is_none());
        assert!(native_path(Path::new("/synthetic/a\\b")).is_none());
        assert_eq!(
            native_path(Path::new("/synthetic/合法")),
            Some("/synthetic/合法")
        );
    }
    #[test]
    fn complete_data_requires_exact_saved_bytes_and_all_child_closure_fields() {
        let decoded = decode_terminal(terminal_value()).unwrap();
        let Frame::Terminal(terminal) = decoded else {
            panic!("terminal required")
        };
        assert!(terminal.lifetime.settled());
        assert!(terminal.public_result().unwrap().get("footprint").is_none());
        for (field, replacement) in [
            ("fatal", json!(true)),
            ("contained", json!(false)),
            ("inputClosed", json!(false)),
            ("handlersRestored", json!(false)),
            ("resourcesClosed", json!(false)),
            ("commands", json!(1)),
            ("profileCalls", json!(1)),
            ("commandDispatched", Value::Null),
            ("stopObserved", json!("cancelled")),
        ] {
            let mut value = terminal_value();
            value["lifetime"][field] = replacement;
            assert!(decode_terminal(value).is_err());
        }
        let mut value = terminal_value();
        value["result"]["footprint"]["files"][0]["sha256"] = json!("f".repeat(64));
        assert!(decode_terminal(value).is_err());
        let mut value = terminal_value();
        value["result"]["footprint"]["files"][0]["identity"]["bytes"] = json!(3);
        assert!(decode_terminal(value).is_err());
        let mut value = terminal_value();
        value["result"]["requirements"]["projectCodeExecuted"] = json!(true);
        assert!(decode_terminal(value).is_err());
        let mut raw = frame(terminal_value(), 1, "terminal");
        raw.push(b'\n');
        assert!(decode(
            &raw,
            &"d".repeat(32),
            &"e".repeat(32),
            &prepare(&context_value()).unwrap()
        )
        .is_err());
    }
    #[test]
    fn staged_sources_never_claim_protected_registration_or_native_finality() {
        let mut context = prepare(&context_value()).unwrap();
        context.action = Action::Acquire;
        context.review = Some(Review {
            operation_id: "0".repeat(32),
            owner_generation: "1".repeat(32),
            requirements_sha256: "b".repeat(64),
        });
        let operation = "d".repeat(32);
        let offered = json!({"schemaVersion":1,"kind":"staged-tool-sources","operationId":operation,
            "contextSha256":"2".repeat(64),"referenceSha256":"3".repeat(64),"projectionSha256":"4".repeat(64),"cacheJob":format!("tool-{operation}"),
            "lookupScope":"registered-selected-known","reusedArchives":["jdk"],"downloadedArchives":["sdk-platform","sdk-build-tools","gradle"],
            "groups":[{"group":"jdk","components":["jdk"],"allRequiredComponentsStaged":true,"next":"choose-native-source"},
                {"group":"sdk","components":["sdk-platform","sdk-build-tools"],"allRequiredComponentsStaged":true,"next":"choose-native-source"},
                {"group":"gradle","components":["gradle"],"allRequiredComponentsStaged":true,"next":"choose-native-source"}],
            "assurance":{"nativeFinality":false,"registered":false,"readyToBuild":false}});
        assert!(result_valid(&offered, &operation, &context).is_ok());
        for field in ["nativeFinality", "registered", "readyToBuild"] {
            let mut value = offered.clone();
            value["assurance"][field] = json!(true);
            assert!(result_valid(&value, &operation, &context).is_err());
        }
        let mut value = offered.clone();
        value["reusedArchives"] = json!(["jdk", "gradle"]);
        assert!(result_valid(&value, &operation, &context).is_err());
        assert!(result_valid(&offered, &"e".repeat(32), &context).is_err());
    }
}
