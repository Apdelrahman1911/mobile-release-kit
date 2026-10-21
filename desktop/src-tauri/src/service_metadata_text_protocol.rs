//! Closed public-text comparison DATA. No root, filename, credential, command,
//! recovery or write permission is supplied by this transport. Native Load and
//! the original MetadataText editor remain the only source/write authorities.
pub use crate::service_configuration_protocol::{
    Allow, Apply, Effect, Final, Journal, Original, Query,
};
use crate::service_protocol::{Error, Id};
use serde::{de::DeserializeSeed, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const REQUEST_BYTES: usize = 256 * 1024;
pub const STDIN_BYTES: usize = REQUEST_BYTES - 4096;
pub const STATUS_BYTES: usize = 8 * 1024;
pub const TEXT_BYTES: usize = 32 * 1024;
pub const READ_BYTES: usize = 256 * 1024;
pub const REVIEW_MS: u64 = 15 * 60 * 1000;
pub const CONSENT: &str = "agent-exact-metadata-text-preview-v1";
pub(crate) const INPUT_NODES: usize = 128;
pub(crate) const TYPED_INPUT_BYTES: usize = 5 * TEXT_BYTES + 8192;
pub(crate) const IPC_PEAK: usize = 5 * REQUEST_BYTES + INPUT_NODES * 1024 + TYPED_INPUT_BYTES;
// One entire Metadata exchange is now try-admitted by the ORIGINAL Endpoint.
// All eight workers can still hold an ordinary <=4KiB decode before its method
// is known. Reserve each Seed's128 nodes PLUS64KiB raw/string/field-vector
// overlap and two actual Request cells (small Prepare decodes twice). The
// large request/response cap is unchanged; no credit removes old family debits.
pub(crate) const SMALL_INPUT_PEAK: usize = INPUT_NODES * 1024
    + 16 * crate::service_protocol::REQUEST_BYTES
    + 2 * std::mem::size_of::<crate::service_protocol::Request>();
pub(crate) const IPC_BACKING: usize = IPC_PEAK + 8 * SMALL_INPUT_PEAK;
pub(crate) const NATIVE_FRAME_BYTES: usize = (768 + 16) * 1024;
pub(crate) const NATIVE_FRAME_NODES: usize = 1024;
pub(crate) const NATIVE_COMMAND_BYTES: usize = 272 * 1024;

fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
/// Count BEFORE allocation. Vec capacity is fixed to the checked encoded size;
/// old service encoders and their limits are unchanged.
pub(crate) fn encoded<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, Error> {
    struct Count {
        n: usize,
        limit: usize,
    }
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.n = self
                .n
                .checked_add(b.len())
                .filter(|n| *n <= self.limit)
                .ok_or(std::io::ErrorKind::InvalidData)?;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut n = Count { n: 0, limit };
    serde_json::to_writer(&mut n, value).map_err(|_| Error::InvalidRequest)?;
    let mut bytes = Vec::with_capacity(n.n);
    serde_json::to_writer(&mut bytes, value).map_err(|_| Error::InvalidRequest)?;
    if bytes.len() != n.n {
        return Err(Error::StateUnknown);
    }
    Ok(bytes)
}
pub(crate) fn bounded<T: Serialize>(value: &T, limit: usize) -> Result<(), Error> {
    // The returned fixed-capacity scratch is part of the named IPC/native quote.
    encoded(value, limit).map(|_| ())
}
fn strict(bytes: &[u8], limit: usize, nodes: usize, depth: usize) -> Result<Value, Error> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(Error::InvalidRequest);
    }
    std::str::from_utf8(bytes).map_err(|_| Error::InvalidRequest)?;
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let mut n = 0;
    let v = crate::bounded_json_seed::Seed {
        nodes: &mut n,
        depth: 0,
        node_limit: nodes,
        depth_limit: depth,
    }
    .deserialize(&mut d)
    .map_err(|_| Error::InvalidRequest)?;
    d.end().map_err(|_| Error::InvalidRequest)?;
    Ok(v)
}
/// No old RequestBody or unconstrained Value is ever decoded on the large path.
/// All keys/containers are bounded by the SAME original Seed before conversion.
pub(crate) fn decode_prepare_request(
    bytes: &[u8],
) -> Result<crate::service_protocol::Request, Error> {
    let value = strict(bytes, REQUEST_BYTES, INPUT_NODES, 8)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        version: u32,
        #[serde(rename = "requestId")]
        request_id: Id,
        request: Body,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        method: Method,
        params: Prepare,
    }
    #[derive(Deserialize)]
    enum Method {
        #[serde(rename = "metadata-text.prepare")]
        Prepare,
    }
    let e = Envelope::deserialize(value).map_err(|_| Error::InvalidRequest)?;
    if e.version != crate::service_protocol::VERSION {
        return Err(Error::InvalidRequest);
    }
    let _ = e.request.method;
    e.request.params.validate()?;
    Ok(crate::service_protocol::Request {
        version: e.version,
        request_id: e.request_id,
        request: crate::service_protocol::RequestBody::MetadataTextPrepare(e.request.params),
    })
}
pub fn decode_fields(bytes: &[u8]) -> Result<Fields, Error> {
    let v = strict(bytes, STDIN_BYTES, INPUT_NODES, 8)?;
    let p = Fields::deserialize(v).map_err(|_| Error::InvalidRequest)?;
    p.validate()?;
    Ok(p)
}
pub(crate) fn strict_small_request(bytes: &[u8]) -> Result<Value, Error> {
    strict(bytes, 4096, INPUT_NODES, 8)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Android,
    Ios,
}
impl Platform {
    pub fn ids(self) -> &'static [&'static str] {
        match self {
            Self::Android => &["title.txt", "short_description.txt", "full_description.txt"],
            Self::Ios => &[
                "description.txt",
                "keywords.txt",
                "privacy_url.txt",
                "support_url.txt",
                "release_notes.txt",
            ],
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
        }
    }
}
pub fn locale(s: &str) -> bool {
    (2..=12).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
pub(crate) fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub id: String,
    pub text: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fields {
    pub platform: Platform,
    pub fields: Vec<Field>,
}
impl Fields {
    pub fn validate(&self) -> Result<(), Error> {
        if self.fields.len() != self.platform.ids().len()
            || !self
                .fields
                .iter()
                .zip(self.platform.ids())
                .all(|(f, id)| f.id == *id && f.text.len() <= TEXT_BYTES)
        {
            return Err(Error::InvalidRequest);
        }
        bounded(self, STDIN_BYTES)
    }
    pub(crate) fn digest(&self) -> Result<String, Error> {
        Ok(sha(&encoded(self, STDIN_BYTES)?))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Read {
    pub origin: Query,
    pub expected_observation_revision: u64,
    pub platform: Platform,
    pub locale: String,
}
impl Read {
    pub fn validate(&self) -> Result<(), Error> {
        if self.expected_observation_revision == 0 || !locale(&self.locale) {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepare {
    pub origin: Query,
    pub proposal: Fields,
}
impl Prepare {
    pub fn validate(&self) -> Result<(), Error> {
        self.proposal.validate()?;
        bounded(self, REQUEST_BYTES - 1024)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DigestData {
    pub byte_length: u32,
    pub sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum BaselineField {
    Absent {
        id: String,
    },
    Present {
        id: String,
        #[serde(rename = "byteLength")]
        byte_length: u32,
        sha256: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub config: DigestData,
    pub fields: Vec<BaselineField>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum ObservedField {
    Absent {
        id: String,
        path: String,
    },
    Present {
        id: String,
        path: String,
        text: String,
        #[serde(rename = "byteLength")]
        byte_length: u32,
        sha256: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assurance {
    pub basis: String,
    pub project_code_executed: bool,
    pub tools_probed: bool,
    pub credentials_read: bool,
    pub git_observed: bool,
    pub store_contacted: bool,
    pub writes_performed: bool,
    pub release_readiness: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub schema_version: u32,
    pub platform: Platform,
    pub locale: String,
    pub metadata_root: String,
    pub observation_scope: String,
    pub baseline: Baseline,
    pub fields: Vec<ObservedField>,
    pub assurance: Assurance,
}
impl Observation {
    pub fn validate(&self) -> Result<(), Error> {
        let a = &self.assurance;
        if self.schema_version != 1
            || !locale(&self.locale)
            || self.metadata_root.len() > 512
            || self.metadata_root.is_empty()
            || self.metadata_root.starts_with('/')
            || self
                .metadata_root
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
            || self
                .metadata_root
                .chars()
                .any(|c| c.is_control() || c == '\\')
            || self.observation_scope != "single-request-non-atomic"
            || a.basis != "static-text"
            || a.project_code_executed
            || a.tools_probed
            || a.credentials_read
            || a.git_observed
            || a.store_contacted
            || a.writes_performed
            || a.release_readiness != "unknown"
            || !(1..=512 * 1024).contains(&self.baseline.config.byte_length)
            || !hex(&self.baseline.config.sha256)
            || self.fields.len() != self.platform.ids().len()
            || self.baseline.fields.len() != self.fields.len()
        {
            return Err(Error::InvalidRequest);
        }
        for ((f, b), id) in self
            .fields
            .iter()
            .zip(&self.baseline.fields)
            .zip(self.platform.ids())
        {
            let expected = format!(
                "{}/{}/{}/{}",
                self.metadata_root,
                self.platform.name(),
                self.locale,
                id
            );
            let good = match (f, b) {
                (ObservedField::Absent { id: f, path }, BaselineField::Absent { id: b }) => {
                    f == id && b == id && path == &expected
                }
                (
                    ObservedField::Present {
                        id: f,
                        path,
                        text,
                        byte_length,
                        sha256,
                    },
                    BaselineField::Present {
                        id: b,
                        byte_length: n,
                        sha256: h,
                    },
                ) => {
                    f == id
                        && b == id
                        && path == &expected
                        && *byte_length as usize == text.len()
                        && text.len() <= TEXT_BYTES
                        && byte_length == n
                        && sha256 == h
                        && hex(h)
                        && sha(text.as_bytes()) == *h
                }
                _ => false,
            };
            if !good {
                return Err(Error::InvalidRequest);
            }
        }
        bounded(self, READ_BYTES - 4096)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    QueuedRead,
    Reading,
    Loaded,
    QueuedPrepare,
    Opening,
    Opened,
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
    pub id: String,
    pub action: String,
    #[serde(deserialize_with = "nullable")]
    pub before_bytes: Option<u32>,
    pub after_bytes: u32,
    pub after_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub plan_token: Id,
    pub native_status_revision: u32,
    pub proposal_sha256: String,
    pub files: Vec<File>,
}
impl Review {
    pub fn validate(&self, platform: Platform) -> Result<(), Error> {
        if self.native_status_revision == 0
            || !hex(&self.proposal_sha256)
            || self.files.len() != platform.ids().len()
            || !self.files.iter().zip(platform.ids()).all(|(f, id)| {
                f.id == *id
                    && matches!(f.action.as_str(), "create" | "replace" | "preserve")
                    && f.before_bytes.is_none_or(|n| n as usize <= TEXT_BYTES)
                    && f.after_bytes as usize <= TEXT_BYTES
                    && hex(&f.after_sha256)
            })
        {
            return Err(Error::InvalidRequest);
        }
        bounded(self, 4096)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub schema_version: u32,
    pub origin: Query,
    pub revision: u32,
    pub runtime_project_id: String,
    pub platform: Platform,
    pub locale: String,
    pub phase: Phase,
    #[serde(deserialize_with = "nullable")]
    pub observation: Option<Observation>,
    #[serde(deserialize_with = "nullable")]
    pub original: Option<Original>,
    #[serde(deserialize_with = "nullable")]
    pub proposal_sha256: Option<String>,
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
            || !locale(&self.locale)
            || self.remaining_ms > REVIEW_MS
            || self.permission_live != (self.remaining_ms > 0)
            || self.permission_live
                && (self.phase != Phase::Reviewing || self.apply_consumed || self.cancel_requested)
            || self.result.is_some() != (self.phase == Phase::Final)
            || self.proposal_sha256.as_ref().is_some_and(|s| !hex(s))
            || self.review.is_some() && (self.original.is_none() || self.proposal_sha256.is_none())
            || matches!(self.phase, Phase::QueuedApply | Phase::Applying)
                && (!self.apply_consumed || self.review.is_none())
            || self.observation.is_some() && self.phase != Phase::Loaded
        {
            return Err(Error::InvalidRequest);
        }
        if let Some(o) = &self.observation {
            if o.platform != self.platform || o.locale != self.locale {
                return Err(Error::InvalidRequest);
            }
            o.validate()?;
        }
        if let Some(r) = &self.review {
            r.validate(self.platform)?;
            if Some(&r.proposal_sha256) != self.proposal_sha256.as_ref() {
                return Err(Error::InvalidRequest);
            }
        }
        bounded(
            self,
            if self.observation.is_some() {
                READ_BYTES - 1024
            } else {
                STATUS_BYTES - 1024
            },
        )
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
#[path = "service_metadata_text_protocol_tests.rs"]
mod tests;
