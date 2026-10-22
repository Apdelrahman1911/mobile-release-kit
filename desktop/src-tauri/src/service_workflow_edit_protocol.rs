//! Compact local four-caller workflow-edit DATA. The draft, full inventory and
//! toolkit inputs belong to the real MAIN WorkflowEdit owner, never IPC.
pub use crate::service_configuration_protocol::{Apply, Effect, Final, Journal, Original, Query};
use crate::service_protocol::{Error, Id, Settlement};
use serde::{Deserialize, Serialize};
pub const EVENT: &str = "mrk:agent-workflow-edit";
pub const REQUEST_BYTES: usize = 4096;
pub const STATUS_BYTES: usize = 16 * 1024;
pub const CONSENT: &str = "agent-exact-workflow-preview-v1";
/// Only the installed macOS original has this separately bounded CODE profile.
/// Ordinary Linux workflow editing is unchanged; no runtime fallback is granted.
pub fn platform_supported() -> bool {
    cfg!(all(target_os="macos", target_pointer_width="64", any(target_arch="aarch64",target_arch="x86_64")))
}
pub(crate) use crate::service_metadata_images_protocol::bounded;
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepare {
    pub origin: Query,
    pub expected_observation_revision: u64,
}
impl Prepare {
    pub fn validate(&self) -> Result<(), Error> {
        if self.expected_observation_revision == 0 {
            return Err(Error::InvalidRequest);
        }
        bounded(self, REQUEST_BYTES)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    QueuedOpen,
    Opening,
    Opened,
    Preparing,
    Reviewing,
    QueuedApply,
    Applying,
    Stopping,
    Refused,
    Final,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileId { Preflight, Candidate, ExternalTesting, ProductionSubmit }
pub const IDS: [FileId; 4] = [FileId::Preflight, FileId::Candidate, FileId::ExternalTesting, FileId::ProductionSubmit];
impl FileId {
    pub fn path(self) -> &'static str { match self {
        Self::Preflight => ".github/workflows/mobile-preflight.yml",
        Self::Candidate => ".github/workflows/mobile-candidate.yml",
        Self::ExternalTesting => ".github/workflows/mobile-external-testing.yml",
        Self::ProductionSubmit => ".github/workflows/mobile-production-submit.yml",
    }}
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileAction { Create, Preserve, Update }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bytes { pub byte_length: u32, pub sha256: String }
fn hex(s: &str, len: usize) -> bool { s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
impl Bytes { fn valid(&self, generated: bool) -> bool {
    self.byte_length <= if generated { 16384 } else { 1024 * 1024 }
        && (!generated || self.byte_length > 0) && hex(&self.sha256, 64)
}}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct File {
    pub id: FileId, pub action: FileAction,
    #[serde(deserialize_with = "nullable")]
    pub observed: Option<Bytes>,
    pub generated: Bytes,
}
impl File { fn valid(&self) -> bool {
    self.generated.valid(true) && match (&self.action, &self.observed) {
        (FileAction::Create, None) => true,
        (FileAction::Preserve, Some(old)) => old.valid(false) && old == &self.generated,
        (FileAction::Update, Some(old)) => old.valid(true) && old.sha256 != self.generated.sha256,
        _ => false,
    }
}}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub plan_token: Id,
    pub native_status_revision: u32,
    pub draft_revision: u32,
    pub baseline_generation: u32,
    pub files: [File; 4],
    pub created_directories: u8,
    pub core_version: String,
    pub resource_version: u32,
    pub resource_sha256: String,
    pub tooling_repository: String,
    pub tooling_sha: String,
}
pub(crate) fn runtime_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
fn coordinate(repository: &str, sha: &str) -> bool {
    let Some((owner, repo)) = repository.split_once('/') else {
        return false;
    };
    let part = |s: &str, max: usize, punct: &[u8]| {
        !s.is_empty()
            && s.len() <= max
            && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            && s.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || punct.contains(&b))
    };
    part(owner, 39, b"-")
        && part(repo, 100, b"._-")
        && sha.len() == 40
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Review {
    pub fn validate(&self) -> Result<(), Error> {
        let mut parts = self.core_version.split('.');
        let valid_version = (0..3).all(|_| parts.next().is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))) && parts.next().is_none();
        if [self.native_status_revision,self.draft_revision,self.baseline_generation].contains(&u32::MAX)
            || self.created_directories > 2
            || self.files.iter().zip(IDS).any(|(f,id)| f.id != id || !f.valid())
            || self.created_directories != 0 && self.files.iter().any(|f| f.action != FileAction::Create)
            || self.core_version.len() > 32 || !valid_version
            || self.resource_version != 1 || !hex(&self.resource_sha256,64)
            || !coordinate(&self.tooling_repository,&self.tooling_sha)
        { return Err(Error::InvalidRequest); }
        bounded(self,4096)
    }
    pub(crate) fn bounded_backing(&self) -> bool {
        self.tooling_repository.capacity() <= 256 && self.tooling_sha.capacity() <= 64
            && self.core_version.capacity() <= 64 && self.resource_sha256.capacity() <= 128
            && self.files.iter().all(|f| f.generated.sha256.capacity() <= 128 && f.observed.as_ref().is_none_or(|o| o.sha256.capacity() <= 128))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Allow {
    pub origin: Query,
    pub original: Original,
    pub plan_token: Id,
    pub expected_native_status_revision: u32,
    pub expected_request_revision: u32,
    pub consent_version: String,
}
impl Allow {
    pub fn validate(&self) -> Result<(), Error> {
        if self.expected_request_revision == 0
            || self.expected_request_revision == u32::MAX
            || self.expected_native_status_revision == u32::MAX
            || self.consent_version != CONSENT
        {
            return Err(Error::InvalidRequest);
        }
        bounded(self, REQUEST_BYTES)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub schema_version: u32,
    pub origin: Query,
    pub runtime_project_id: String,
    pub revision: u32,
    pub phase: Phase,
    pub settlement: Settlement,
    #[serde(deserialize_with = "nullable")]
    pub original: Option<Original>,
    #[serde(deserialize_with = "nullable")]
    pub review: Option<Review>,
    pub permission_available: bool,
    pub permission_consumed: bool,
    pub remaining_ms: u64,
    pub cancel_requested: bool,
    #[serde(deserialize_with = "nullable")]
    pub result: Option<Final>,
    pub do_not_replay: bool,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || self.revision == 0
            || self.revision == u32::MAX
            || !runtime_id(&self.runtime_project_id)
            || !self.do_not_replay
            || self.remaining_ms > 900_000
            || self.settlement
                != match self.phase {
                    Phase::Final => Settlement::Settled,
                    Phase::Unknown => Settlement::Unknown,
                    _ => Settlement::Pending,
                }
            || (self.phase == Phase::Final) != self.result.is_some()
            || self.review.is_some() && self.original.is_none()
            || self.permission_available
                && (self.permission_consumed
                    || self.cancel_requested
                    || self.phase != Phase::Reviewing
                    || self.review.is_none())
            || self.permission_consumed && self.review.is_none()
            || matches!(
                self.phase,
                Phase::Opened
                    | Phase::Preparing
                    | Phase::Reviewing
                    | Phase::QueuedApply
                    | Phase::Applying
            ) && self.original.is_none()
            || matches!(
                self.phase,
                Phase::Reviewing | Phase::QueuedApply | Phase::Applying
            ) && self.review.is_none()
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(v) = &self.review {
            v.validate()?;
        }
        bounded(self, STATUS_BYTES)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopStatus {
    pub service_instance: Id,
    #[serde(deserialize_with = "nullable")]
    pub request: Option<Status>,
}
impl DesktopStatus {
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(s) = &self.request {
            if s.origin.service_instance != self.service_instance {
                return Err(Error::InvalidRequest);
            }
            s.validate()?;
        }
        bounded(self, STATUS_BYTES)
    }
}

#[cfg(test)]
#[path = "service_workflow_edit_protocol_tests.rs"]
mod tests;
