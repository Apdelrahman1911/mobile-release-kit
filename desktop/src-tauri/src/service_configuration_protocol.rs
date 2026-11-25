//! Closed comparison DATA for the running Desktop's original Configuration
//! EditOwner. No full config, arbitrary filesystem operation, command,
//! credential or grant is accepted. READ is not Apply permission.
use crate::service_protocol::{Error, Id};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CHANGE_BYTES: usize = 2048;
pub const STATUS_BYTES: usize = 16 * 1024;
pub const REQUEST_LIMIT: usize = 32;
pub const CONSENT: &str = "agent-exact-configuration-preview-v1";
pub const REVIEW_MS: u64 = 15 * 60 * 1000;

// This interface's ONE extra full-value derivation is narrower than ordinary
// Config editing. Bound containers as well as bytes before any clone: tiny
// maps cannot turn a small encoded config into an unaccounted heap. The
// existing owner already retains the original checkout; no parse or source
// replacement happens here. Oversize configs keep the ordinary Desktop path.
pub(crate) fn derivation_bound(base: &Value) -> Result<(), Error> {
    fn visit(v: &Value, depth: usize, left: &mut usize) -> Result<(), Error> {
        if depth > 20 || *left == 0 {
            return Err(Error::Conflict);
        }
        *left -= 1;
        match v {
            Value::Array(a) => {
                for child in a {
                    visit(child, depth + 1, left)?;
                }
            }
            Value::Object(o) => {
                for child in o.values() {
                    if *left == 0 {
                        return Err(Error::Conflict);
                    }
                    *left -= 1; // Each original map key is backing too.
                    visit(child, depth + 1, left)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= 256 * 1024)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    visit(base, 0, &mut 4096)?;
    serde_json::to_writer(Count(0), base).map_err(|_| Error::Conflict)
}

fn nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}
fn bounded<T: Serialize>(value: &T, limit: usize) -> Result<(), Error> {
    if serde_json::to_vec(value)
        .map_err(|_| Error::InvalidRequest)?
        .len()
        > limit
    {
        Err(Error::InvalidRequest)
    } else {
        Ok(())
    }
}
fn text(s: &str, limit: usize) -> bool {
    !s.is_empty()
        && s.len() <= limit
        && s.bytes().all(|c| (0x20..0x7f).contains(&c))
        && s.bytes().any(|c| c != b' ')
}
fn branch(s: &str) -> bool {
    text(s, 255)
        && !s.starts_with('/')
        && !s.ends_with(['.', '/'])
        && !["..", "//", "@{"].iter().any(|v| s.contains(v))
        && !s.bytes().any(|c| b" ~^:?*[\\".contains(&c))
}
fn module(s: &str) -> bool {
    s.len() <= 512
        && (s == ":"
            || s.starts_with(':')
                && s[1..].split(':').all(|p| {
                    !p.is_empty()
                        && p.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                }))
}
fn variant(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
fn relative(s: &str) -> bool {
    text(s, 512)
        && !s.starts_with('/')
        && !s.contains(['\\', ':'])
        && s.split('/').count() <= 16
        && s.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
}

// Exact core metadata vocabulary (config.py), with this CLI's additional
// finite 32-total/2KiB profile. These are values, never path handles.
fn metadata_root(s: &str) -> bool {
    fn core_space(c: char) -> bool {
        c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
    }
    !s.is_empty()
        && s.len() <= 4 * 512
        && s.chars().count() <= 512
        && s.chars().any(|c| !core_space(c))
        && !s.contains(['\0', '\n', '\r', '\\'])
        && !s.starts_with('/')
        && !(s.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && s.as_bytes().get(1) == Some(&b':'))
        && s.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
}
fn locale(s: &str) -> bool {
    let mut parts = s.split('-');
    let language = parts.next().unwrap_or("");
    if !(2..=3).contains(&language.len()) || !language.bytes().all(|c| c.is_ascii_lowercase()) {
        return false;
    }
    let mut region = parts.next();
    if region.is_some_and(|p| {
        p.len() == 4
            && p.as_bytes()[0].is_ascii_uppercase()
            && p.as_bytes()[1..].iter().all(u8::is_ascii_lowercase)
    }) {
        region = parts.next();
    }
    region.is_none_or(|p| {
        p.len() == 2 && p.bytes().all(|c| c.is_ascii_uppercase())
            || p.len() == 3 && p.bytes().all(|c| c.is_ascii_digit())
    }) && parts.next().is_none()
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    // Fixed admitted DATA, not growable collections. Boxed strings/slices
    // retain their actual lengths across all five original Row copies.
    pub root: Box<str>,
    pub android_locales: Box<[Box<str>]>,
    pub ios_locales: Box<[Box<str>]>,
}
impl Metadata {
    fn valid(&self) -> bool {
        metadata_root(&self.root)
            && self
                .android_locales
                .len()
                .saturating_add(self.ios_locales.len())
                <= 32
            && [&self.android_locales, &self.ios_locales]
                .into_iter()
                .all(|values| {
                    values.len() <= 32
                        && values
                            .iter()
                            .enumerate()
                            .all(|(n, value)| locale(value) && !values[..n].contains(value))
                })
            && bounded(self, CHANGE_BYTES - b"\"kind\":\"metadata\",".len()).is_ok()
    }
    fn valid_for(&self, android: bool, ios: bool) -> bool {
        self.valid()
            && (!android || !self.android_locales.is_empty())
            && (!ios || !self.ios_locales.is_empty())
    }
    fn from_value(value: &Value, android: bool, ios: bool) -> Option<Self> {
        let object = value.as_object()?;
        if object.len() != 3 {
            return None;
        }
        let root = object.get("root")?.as_str()?;
        let a = object.get("androidLocales")?.as_array()?;
        let i = object.get("iosLocales")?.as_array()?;
        // Bound all borrowed data BEFORE allocating its typed copy. An absent
        // projection never means an absent/default metadata configuration.
        if !metadata_root(root)
            || a.len().saturating_add(i.len()) > 32
            || a.iter().chain(i).any(|v| !v.as_str().is_some_and(locale))
        {
            return None;
        }
        let result = Self {
            root: root.into(),
            android_locales: a
                .iter()
                .map(|v| Box::<str>::from(v.as_str().unwrap()))
                .collect(),
            ios_locales: i
                .iter()
                .map(|v| Box::<str>::from(v.as_str().unwrap()))
                .collect(),
        };
        result.valid_for(android, ios).then_some(result)
    }
}
fn optional_metadata<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Metadata>, D::Error> {
    // Missing is the old projection. Explicit null is not an omission.
    Metadata::deserialize(d).map(Some)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Source {
    pub candidate_branch: String,
    pub production_branch: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Android {
    #[serde(deserialize_with = "nullable")]
    pub module: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub variant: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "path",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum Container {
    Project(String),
    Workspace(String),
}
impl Container {
    fn valid(&self) -> bool {
        match self {
            Self::Project(p) => relative(p) && p.ends_with(".xcodeproj"),
            Self::Workspace(p) => relative(p) && p.ends_with(".xcworkspace"),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ios {
    #[serde(deserialize_with = "nullable")]
    pub container: Option<Container>,
    #[serde(deserialize_with = "nullable")]
    pub scheme: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub archive_configuration: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub source: Source,
    #[serde(deserialize_with = "nullable")]
    pub android: Option<Android>,
    #[serde(deserialize_with = "nullable")]
    pub ios: Option<Ios>,
    #[serde(default, deserialize_with = "optional_metadata", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}
impl Settings {
    pub fn validate(&self) -> Result<(), Error> {
        if !branch(&self.source.candidate_branch)
            || !branch(&self.source.production_branch)
            || self.android.as_ref().is_some_and(|a| {
                a.module.as_deref().is_some_and(|s| !module(s))
                    || a.variant.as_deref().is_some_and(|s| !variant(s))
            })
            || self.ios.as_ref().is_some_and(|i| {
                i.container.as_ref().is_some_and(|c| !c.valid())
                    || i.scheme.as_deref().is_some_and(|s| !text(s, 255))
                    || i.archive_configuration
                        .as_deref()
                        .is_some_and(|s| !text(s, 255))
            })
            || self.metadata.as_ref().is_some_and(|m| !m.valid_for(self.android.is_some(), self.ios.is_some()))
        {
            return Err(Error::InvalidRequest);
        }
        bounded(self, 4096)
    }
    /// Only an original Config checkout calls this. Unknown/missing schema is
    /// refusal; this is not schema validation or a replacement source reader.
    pub(crate) fn from_base(base: &Value) -> Result<Self, Error> {
        fn optional(v: &Value, key: &str) -> Result<Option<String>, Error> {
            match v.get(key) {
                None => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                _ => Err(Error::Conflict),
            }
        }
        if base.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
            return Err(Error::Conflict);
        }
        let source = &base["source"];
        let source = Source {
            candidate_branch: source["candidateBranch"]
                .as_str()
                .ok_or(Error::Conflict)?
                .into(),
            production_branch: source["productionBranch"]
                .as_str()
                .ok_or(Error::Conflict)?
                .into(),
        };
        let a = &base["android"];
        let i = &base["ios"];
        let android = match a["enabled"].as_bool() {
            Some(false) => None,
            Some(true) => Some(Android {
                module: optional(a, "module")?,
                variant: optional(a, "variant")?,
            }),
            None => return Err(Error::Conflict),
        };
        let ios = match i["enabled"].as_bool() {
            Some(false) => None,
            Some(true) => {
                let container = match (optional(i, "project")?, optional(i, "workspace")?) {
                    (Some(p), None) => Some(Container::Project(p)),
                    (None, Some(p)) => Some(Container::Workspace(p)),
                    (None, None) => None,
                    _ => return Err(Error::Conflict),
                };
                Some(Ios {
                    container,
                    scheme: optional(i, "scheme")?,
                    archive_configuration: optional(i, "archiveConfiguration")?,
                })
            }
            None => return Err(Error::Conflict),
        };
        let mut result = Self {
            source,
            android,
            ios,
            metadata: None,
        };
        result.validate()?;
        result.metadata = Metadata::from_value(&base["metadata"], result.android.is_some(), result.ios.is_some());
        // Preserve the old three-group reader even if an otherwise valid
        // metadata value cannot fit the same original projection ceiling.
        if result.validate().is_err() { result.metadata = None; }
        Ok(result)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Change {
    Source {
        candidate_branch: String,
        production_branch: String,
    },
    Android {
        module: String,
        variant: String,
    },
    Ios {
        container: Container,
        scheme: String,
        archive_configuration: String,
    },
    Metadata(Metadata),
}
impl std::fmt::Debug for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfigurationChange(..)")
    }
}
impl Change {
    pub fn validate(&self) -> Result<(), Error> {
        let valid = match self {
            Self::Source {
                candidate_branch,
                production_branch,
            } => branch(candidate_branch) && branch(production_branch),
            Self::Android {
                module: m,
                variant: v,
            } => module(m) && variant(v),
            Self::Ios {
                container,
                scheme,
                archive_configuration,
            } => container.valid() && text(scheme, 255) && text(archive_configuration, 255),
            Self::Metadata(m) => m.valid(),
        };
        if !valid {
            return Err(Error::InvalidRequest);
        }
        bounded(self, CHANGE_BYTES)
    }
    /// Preserve every other JSON value, including commands/identity/credentials
    /// which this interface can neither disclose nor edit. The existing core
    /// still validates the entire schema and exact expectedBase during Prepare.
    pub(crate) fn derive(&self, base: &Value) -> Result<Value, Error> {
        self.validate()?;
        derivation_bound(base)?;
        let prior = Settings::from_base(base)?;
        if let Self::Metadata(m) = self {
            if prior.metadata.is_none() || !m.valid_for(prior.android.is_some(), prior.ios.is_some()) {
                return Err(Error::Conflict);
            }
        }
        let mut next = base.clone();
        match self {
            Self::Source {
                candidate_branch,
                production_branch,
            } => {
                next["source"]["candidateBranch"] = Value::String(candidate_branch.clone());
                next["source"]["productionBranch"] = Value::String(production_branch.clone());
            }
            Self::Android { module, variant } => {
                if prior.android.is_none() {
                    return Err(Error::Conflict);
                }
                next["android"]["module"] = Value::String(module.clone());
                next["android"]["variant"] = Value::String(variant.clone());
            }
            Self::Ios {
                container,
                scheme,
                archive_configuration,
            } => {
                if prior.ios.is_none() {
                    return Err(Error::Conflict);
                }
                let obj = next["ios"].as_object_mut().ok_or(Error::Conflict)?;
                obj.remove("project");
                obj.remove("workspace");
                let (key, path) = match container {
                    Container::Project(p) => ("project", p),
                    Container::Workspace(p) => ("workspace", p),
                };
                obj.insert(key.into(), Value::String(path.clone()));
                obj.insert("scheme".into(), Value::String(scheme.clone()));
                obj.insert(
                    "archiveConfiguration".into(),
                    Value::String(archive_configuration.clone()),
                );
            }
            Self::Metadata(m) => {
                next["metadata"] = serde_json::to_value(m).map_err(|_| Error::InvalidRequest)?;
            }
        }
        let after = Settings::from_base(&next)?;
        if matches!(self, Self::Metadata(m) if after.metadata.as_ref() != Some(m)) {
            return Err(Error::Conflict);
        }
        Ok(next)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub service_instance: Id,
    pub project_id: Id,
    pub request_id: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Read {
    pub origin: Query,
    pub expected_observation_revision: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Original {
    pub session_id: Id,
    pub owner_generation: Id,
    pub revision: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepare {
    pub origin: Query,
    pub original: Original,
    pub change: Change,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Apply {
    pub origin: Query,
    pub original: Original,
    pub plan_token: Id,
    pub reviewed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Allow {
    pub origin: Query,
    pub original: Original,
    pub plan_token: Id,
    pub expected_native_status_revision: u32,
    pub consent_version: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    QueuedRead,
    Opening,
    Opened,
    QueuedPrepare,
    Preparing,
    Reviewing,
    QueuedApply,
    Applying,
    Stopping,
    Final,
    Refused,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct File {
    pub path: String,
    pub action: String,
    #[serde(deserialize_with = "nullable")]
    pub before_bytes: Option<u32>,
    pub after_bytes: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub plan_token: Id,
    pub native_status_revision: u32,
    pub before: Settings,
    pub after: Settings,
    pub files: Vec<File>,
    pub create_release_directory: bool,
    pub rewrites_config_formatting: bool,
    pub ignore_additions: Vec<String>,
}
impl Review {
    pub fn validate(&self) -> Result<(), Error> {
        self.before.validate()?;
        self.after.validate()?;
        if self.native_status_revision == 0
            || self.files.len() != 2
            || self.files[0].path != "release/mobile-release.json"
            || self.files[1].path != ".gitignore"
            || self.files.iter().enumerate().any(|(i, f)| {
                !matches!(
                    f.action.as_str(),
                    "create" | "preserve" | "replace" | "append"
                ) || f.after_bytes > (if i == 0 { 512 * 1024 } else { 1024 * 1024 })
                    || f.before_bytes
                        .is_some_and(|n| n > (if i == 0 { 512 * 1024 } else { 1024 * 1024 }))
            })
            || self.ignore_additions.len() > 16
            || self.ignore_additions.iter().any(|s| !text(s, 128))
        {
            return Err(Error::InvalidRequest);
        }
        bounded(self, 12 * 1024)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    NotStarted,
    Unchanged,
    RolledBack,
    Committed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Journal {
    NotCreated,
    Clean,
    RecoveryRequired,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Final {
    pub effect: Effect,
    pub journal: Journal,
    pub cancelled: bool,
    pub apply_submitted: bool,
}
impl Final {
    pub fn saved(&self) -> bool {
        self.apply_submitted
            && !self.cancelled
            && matches!(
                (self.effect, self.journal),
                (Effect::Committed, Journal::Clean) | (Effect::Unchanged, Journal::NotCreated)
            )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub schema_version: u32,
    pub origin: Query,
    pub revision: u32,
    pub runtime_project_id: String,
    pub phase: Phase,
    #[serde(deserialize_with = "nullable")]
    pub operation_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub owner_generation: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub original: Option<Original>,
    #[serde(deserialize_with = "nullable")]
    pub settings: Option<Settings>,
    #[serde(deserialize_with = "nullable")]
    pub change: Option<Change>,
    #[serde(deserialize_with = "nullable")]
    pub review: Option<Review>,
    pub permission_live: bool,
    pub remaining_ms: u64,
    pub apply_consumed: bool,
    pub cancel_requested: bool,
    #[serde(deserialize_with = "nullable")]
    pub result: Option<Final>,
    pub do_not_replay: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || self.revision == 0
            || !self.do_not_replay
            || !(1..=64).contains(&self.runtime_project_id.len())
            || !self
                .runtime_project_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || self.remaining_ms > REVIEW_MS
            || self.permission_live != (self.remaining_ms > 0)
            || self.permission_live
                && (self.cancel_requested || self.apply_consumed || self.phase != Phase::Reviewing)
            || self.result.is_some() != (self.phase == Phase::Final)
            || self.operation_id.is_some() != self.owner_generation.is_some()
            || self.original.as_ref().is_some_and(|o| {
                Some(&o.session_id) != self.operation_id.as_ref()
                    || Some(&o.owner_generation) != self.owner_generation.as_ref()
            })
            || self.settings.is_some() && self.original.is_none()
            || self.review.is_some() && (self.change.is_none() || self.original.is_none())
            || matches!(self.phase, Phase::QueuedApply | Phase::Applying)
                && (!self.apply_consumed || self.review.is_none())
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(s) = &self.settings {
            s.validate()?
        }
        if let Some(c) = &self.change {
            c.validate()?
        }
        if let Some(r) = &self.review {
            r.validate()?;
            if let Some(Change::Metadata(m)) = &self.change {
                if r.before.metadata.is_none() || r.after.metadata.as_ref() != Some(m)
                    || r.before.source != r.after.source || r.before.android != r.after.android
                    || r.before.ios != r.after.ios {
                    return Err(Error::InvalidRequest);
                }
            }
        }
        bounded(self, STATUS_BYTES)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopStatus {
    pub service_instance: Id,
    pub revision: u32,
    #[serde(deserialize_with = "nullable")]
    pub request: Option<Status>,
}
impl DesktopStatus {
    pub fn validate(&self) -> Result<(), Error> {
        if self.revision == 0 {
            return Err(Error::InvalidRequest);
        }
        if let Some(r) = &self.request {
            if r.origin.service_instance != self.service_instance {
                return Err(Error::InvalidRequest);
            }
            r.validate()?
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_configuration_protocol_tests.rs"]
mod tests;
