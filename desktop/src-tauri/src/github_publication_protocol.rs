//! Closed five-file setup PR data. No token, consent, project read or Git owner.
use crate::{
    error::BridgeError,
    github_connection_protocol::{bounds, coordinate, nullable, numeric_id, GitHubReadControl},
    github_preflight_protocol::{branch, hex, TOOLING_REPOSITORY, TOOLING_SHA},
    github_setup_protocol::SecretRootIdentity,
    protocol::{strict_json, valid_id},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) const PROTOCOL: &str = "mrk-github-setup-publication/1";
pub(crate) const EVENT: &str = "github-setup-publication-status";
pub(crate) const INITIAL_LIMIT: usize = 8192;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const REVIEW_LIMIT: usize = 384 * 1024;
pub(crate) const GO_LIMIT: usize = REVIEW_LIMIT + 8192;
pub(crate) const RESPONSE_LIMIT: usize = 512 * 1024;
pub(crate) const RETAINED_LIMIT: usize = 8 * 1024 * 1024;
pub(crate) const LAST_REVISION: u32 = u32::MAX - 1;
pub(crate) const PATHS: [&str; 5] = [
    "release/mobile-release.json",
    ".github/workflows/mobile-preflight.yml",
    ".github/workflows/mobile-candidate.yml",
    ".github/workflows/mobile-external-testing.yml",
    ".github/workflows/mobile-production-submit.yml",
];
pub(crate) const CONFIRMATION: &str = "Create this five-file setup commit on a NEW branch and open a draft pull request? Only release/mobile-release.json and four canonical workflow callers are included. Version, metadata and application source changes are NOT uploaded. Local Git/index/HEAD are unchanged. Push and pull-request events can start the repository's existing CI. No merge, existing-branch update, workflow dispatch or release is requested. Cancellation does not undo a sent request.";
pub(crate) fn configured() -> bool {
    TOOLING_SHA.is_some_and(|v| hex(v, 40))
}
fn file_limit(index: usize) -> usize {
    if index == 0 {
        65536
    } else {
        16384
    }
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, BridgeError> {
    // Value's ordered object keys match the Python UTF-8 canonical encoder.
    serde_json::to_value(value)
        .and_then(|v| serde_json::to_vec(&v))
        .map_err(|_| BridgeError::protocol())
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    Prepare,
    Publish,
    Pending,
    Reconcile,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    TargetChanged,
    SourceChanged,
    CallerMismatch,
    SourceUnsupported,
    ConfigurationInvalid,
    ResponseInvalid,
    ResponseLimit,
    NoChange,
    BranchExists,
    Unauthorized,
    Forbidden,
    NotFoundOrInaccessible,
    RateLimited,
    NetworkUnavailable,
    TlsFailed,
    Expired,
    Cancelled,
    JournalUnavailable,
    Unresolved,
    Ambiguous,
    ConfigurationChanged,
    ResourcesUnavailable,
    RuntimeUnavailable,
    Unqualified,
    PublisherUnconfigured,
    NotConnected,
    Busy,
    InvalidInput,
    CleanupUnknown,
    ConsentExpired,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Effect {
    None,
    NotSent,
    PotentiallyApplied,
    DraftPrObserved,
    Unresolved,
    BranchObserved,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Step {
    Tree,
    Commit,
    Branch,
    Pull,
}
const STEPS: [Step; 4] = [Step::Tree, Step::Commit, Step::Branch, Step::Pull];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) project_binding: String,
    pub(crate) repository: String,
    pub(crate) account_id: String,
    pub(crate) repository_id: String,
    pub(crate) base: String,
    pub(crate) tooling_repository: String,
    pub(crate) tooling_sha: String,
    pub(crate) marker: String,
}
impl Target {
    pub(crate) fn valid(&self) -> bool {
        hex(&self.project_binding, 64)
            && coordinate(&self.repository)
            && numeric_id(&self.account_id)
            && numeric_id(&self.repository_id)
            && branch(&self.base)
            && self.tooling_repository == TOOLING_REPOSITORY
            && hex(&self.tooling_sha, 40)
            && hex(&self.marker, 32)
    }
    pub(crate) fn head(&self) -> String {
        format!("mrk/setup-{}", self.marker)
    }
    pub(crate) fn same_scope(&self, other: &Self) -> bool {
        self.project_binding == other.project_binding
            && self.repository == other.repository
            && self.account_id == other.account_id
            && self.repository_id == other.repository_id
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fingerprint {
    pub(crate) bytes: u32,
    pub(crate) sha256: String,
}
impl Fingerprint {
    fn valid(&self, maximum: usize) -> bool {
        self.bytes > 0 && self.bytes as usize <= maximum && hex(&self.sha256, 64)
    }
    fn from(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.len() as u32,
            sha256: digest(bytes),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewFile {
    pub(crate) path: String,
    #[serde(deserialize_with = "nullable")]
    pub(crate) before: Option<String>,
    pub(crate) after: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepared {
    pub(crate) protocol: String,
    pub(crate) target: Target,
    pub(crate) base_commit: String,
    pub(crate) base_tree: String,
    pub(crate) desired_tree: String,
    pub(crate) files: Vec<ReviewFile>,
    pub(crate) head: String,
    pub(crate) confirmation: String,
}
impl Prepared {
    pub(crate) fn valid(&self) -> bool {
        self.protocol == PROTOCOL
            && self.target.valid()
            && hex(&self.base_commit, 40)
            && hex(&self.base_tree, 40)
            && hex(&self.desired_tree, 40)
            && self.base_tree != self.desired_tree
            && self.head == self.target.head()
            && self.confirmation == CONFIRMATION
            && self.files.len() == PATHS.len()
            && self.files.iter().enumerate().all(|(index, file)| {
                file.path == PATHS[index]
                    && !file.after.is_empty()
                    && file.after.len() <= file_limit(index)
                    && file
                        .before
                        .as_ref()
                        .is_none_or(|v| !v.is_empty() && v.len() <= file_limit(index))
            })
            && canonical(self).is_ok_and(|v| v.len() <= REVIEW_LIMIT)
    }
    pub(crate) fn summary(&self) -> Summary {
        Summary {
            protocol: self.protocol.clone(),
            target: self.target.clone(),
            base_commit: self.base_commit.clone(),
            base_tree: self.base_tree.clone(),
            desired_tree: self.desired_tree.clone(),
            files: self
                .files
                .iter()
                .map(|v| FileIdentity {
                    path: v.path.clone(),
                    before: v.before.as_ref().map(|v| Fingerprint::from(v.as_bytes())),
                    after: Fingerprint::from(v.after.as_bytes()),
                })
                .collect(),
        }
    }
    pub(crate) fn sha256(&self) -> Result<String, BridgeError> {
        canonical(self).map(|v| digest(&v))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileIdentity {
    pub(crate) path: String,
    #[serde(deserialize_with = "nullable")]
    pub(crate) before: Option<Fingerprint>,
    pub(crate) after: Fingerprint,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Summary {
    pub(crate) protocol: String,
    pub(crate) target: Target,
    pub(crate) base_commit: String,
    pub(crate) base_tree: String,
    pub(crate) desired_tree: String,
    pub(crate) files: Vec<FileIdentity>,
}
impl Summary {
    fn valid(&self) -> bool {
        self.protocol == PROTOCOL
            && self.target.valid()
            && hex(&self.base_commit, 40)
            && hex(&self.base_tree, 40)
            && hex(&self.desired_tree, 40)
            && self.base_tree != self.desired_tree
            && self.files.len() == PATHS.len()
            && self.files.iter().enumerate().all(|(index, file)| {
                file.path == PATHS[index]
                    && file.after.valid(file_limit(index))
                    && file
                        .before
                        .as_ref()
                        .is_none_or(|v| v.valid(file_limit(index)))
            })
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pending {
    pub(crate) summary: Summary,
    pub(crate) claimed: Vec<Step>,
    pub(crate) confirmed: BTreeMap<Step, String>,
}
fn progress(claimed: &[Step], confirmed: &BTreeMap<Step, String>) -> bool {
    claimed.len() <= 4
        && claimed == &STEPS[..claimed.len()]
        && confirmed.len() <= claimed.len()
        && confirmed.len() + 1 >= claimed.len()
        && confirmed
            .keys()
            .copied()
            .eq(STEPS[..confirmed.len()].iter().copied())
        && confirmed.iter().all(|(step, id)| {
            if *step == Step::Pull {
                numeric_id(id)
            } else {
                hex(id, 40)
            }
        })
        && confirmed
            .get(&Step::Branch)
            .is_none_or(|v| Some(v) == confirmed.get(&Step::Commit))
}
impl Pending {
    pub(crate) fn valid(&self) -> bool {
        self.summary.valid()
            && progress(&self.claimed, &self.confirmed)
            && self
                .confirmed
                .get(&Step::Tree)
                .is_none_or(|v| v == &self.summary.desired_tree)
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Source {
    pub(crate) root: String,
    pub(crate) root_identity: SecretRootIdentity,
}
impl Source {
    pub(crate) fn valid(&self) -> bool {
        let decimal = |v: &str| v.parse::<u64>().is_ok_and(|n| n.to_string() == v);
        self.root.starts_with('/')
            && self.root.len() <= 4096
            && !self.root.chars().any(char::is_control)
            && self
                .root
                .split('/')
                .skip(1)
                .all(|v| !v.is_empty() && v != "." && v != "..")
            && decimal(&self.root_identity.device)
            && decimal(&self.root_identity.inode)
            && self.root_identity.mode & 0o170000 == 0o040000
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) kind: Kind,
    pub(crate) target: Target,
    pub(crate) source: Option<Source>,
    pub(crate) home: Option<String>,
    pub(crate) prepared: Option<Prepared>,
}
impl Request {
    pub(crate) fn valid(&self) -> bool {
        self.target.valid()
            && matches!(self.kind, Kind::Prepare | Kind::Publish) == self.source.is_some()
            && self.source.as_ref().is_none_or(Source::valid)
            && (self.kind == Kind::Prepare) == self.home.is_none()
            && self.home.as_ref().is_none_or(|v| {
                v.starts_with('/') && v.len() <= 4016 && !v.chars().any(char::is_control)
            })
            && (self.kind == Kind::Publish) == self.prepared.is_some()
            && self
                .prepared
                .as_ref()
                .is_none_or(|v| v.valid() && v.target == self.target)
    }
}
fn frame(raw: &[u8], maximum: usize, nodes: usize) -> Result<Value, BridgeError> {
    if raw.len() < 3 || raw.len() > maximum || !raw.ends_with(b"\n") {
        return Err(BridgeError::protocol());
    }
    let body = &raw[..raw.len() - 1];
    if body.first() != Some(&b'{')
        || body.last() != Some(&b'}')
        || body.iter().any(|v| matches!(v, b'\n' | b'\r'))
    {
        return Err(BridgeError::protocol());
    }
    let value = strict_json(body)?;
    if !bounds(&value, maximum, nodes, 12) {
        return Err(BridgeError::protocol());
    }
    // Named structs must never accept Serde positional arrays. Only these
    // three actual collections exist anywhere in this closed wire schema.
    fn shape(value: &Value, key: &str) -> bool {
        match value {
            Value::Array(rows) => {
                matches!(key, "files" | "claimed" | "pending") && rows.iter().all(|v| shape(v, ""))
            }
            Value::Object(rows) => rows.iter().all(|(k, v)| shape(v, k)),
            _ => true,
        }
    }
    if !shape(&value, "") {
        return Err(BridgeError::protocol());
    }
    Ok(value)
}
pub(crate) fn encode_initial(id: &str, request: &Request) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !request.valid() {
        return Err(BridgeError::invalid());
    }
    let prepared_sha256 = request
        .prepared
        .as_ref()
        .map(Prepared::sha256)
        .transpose()?;
    let value = serde_json::json!({"protocol":PROTOCOL,"id":id,"action":{"kind":request.kind,"target":request.target,
        "source":request.source,"home":request.home,"preparedSha256":prepared_sha256}});
    let mut raw = serde_json::to_vec(&value).map_err(|_| BridgeError::invalid())?;
    raw.push(b'\n');
    if raw.len() > INITIAL_LIMIT {
        return Err(BridgeError::invalid());
    }
    Ok(raw)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready {
    request_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyEnvelope {
    protocol: String,
    id: String,
    ready: Ready,
}
pub(crate) fn decode_ready(raw: &[u8], id: &str, expected: &str) -> Result<(), BridgeError> {
    let value: ReadyEnvelope = serde_json::from_value(frame(raw, READY_LIMIT, 32)?)
        .map_err(|_| BridgeError::protocol())?;
    if value.protocol != PROTOCOL || value.id != id || value.ready.request_sha256 != expected {
        return Err(BridgeError::protocol());
    }
    Ok(())
}
pub(crate) fn encode_go(
    id: &str,
    expected: &str,
    token: Option<&str>,
    request: &Request,
) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id)
        || !hex(expected, 64)
        || !request.valid()
        || (request.kind == Kind::Pending) != token.is_none()
        || token.is_some_and(|v| {
            v.is_empty() || v.len() > 4096 || !v.bytes().all(|b| (0x21..=0x7e).contains(&b))
        })
    {
        return Err(BridgeError::invalid());
    }
    let mut raw = Vec::with_capacity(GO_LIMIT);
    raw.extend_from_slice(b"{\"protocol\":\"mrk-github-setup-publication/1\",\"id\":");
    serde_json::to_writer(&mut raw, id).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b",\"go\":{\"requestSha256\":");
    serde_json::to_writer(&mut raw, expected).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b",\"prepared\":");
    serde_json::to_writer(&mut raw, &request.prepared).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b",\"token\":");
    serde_json::to_writer(&mut raw, &token).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b"}}\n");
    if raw.len() > GO_LIMIT {
        return Err(BridgeError::invalid());
    }
    Ok(raw)
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pull {
    pub(crate) number: String,
    pub(crate) url: String,
    pub(crate) commit: String,
}
impl Pull {
    fn valid(&self, target: &Target) -> bool {
        numeric_id(&self.number)
            && hex(&self.commit, 40)
            && self.url
                == format!(
                    "https://github.com/{}/pull/{}",
                    target.repository, self.number
                )
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Publication {
    pub(crate) effect: Effect,
    pub(crate) reason: Reason,
    #[serde(deserialize_with = "nullable")]
    pub(crate) pull: Option<Pull>,
    pub(crate) claimed: Option<Vec<Step>>,
    pub(crate) confirmed: Option<BTreeMap<Step, String>>,
    pub(crate) control: GitHubReadControl,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Configuration {
    pub(crate) saved_config: Fingerprint,
    pub(crate) canonical_config: Fingerprint,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultData {
    pub(crate) schema_version: u32,
    pub(crate) kind: Kind,
    pub(crate) reason: Reason,
    #[serde(deserialize_with = "nullable")]
    pub(crate) prepared: Option<Prepared>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) publication: Option<Publication>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) pending: Option<Vec<Pending>>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) configuration: Option<Configuration>,
    pub(crate) control: GitHubReadControl,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply {
    pub(crate) protocol: String,
    pub(crate) id: String,
    pub(crate) result: ResultData,
}
impl ResultData {
    fn valid(&self, request: &Request) -> bool {
        if self.schema_version != 1
            || self.kind != request.kind
            || !self.control.valid()
            || self.configuration.as_ref().is_some_and(|v| {
                !matches!(self.kind, Kind::Prepare | Kind::Publish)
                    || !v.saved_config.valid(65536)
                    || !v.canonical_config.valid(512 * 1024)
            })
        {
            return false;
        }
        match self.kind {
            Kind::Prepare => {
                self.publication.is_none()
                    && self.pending.is_none()
                    && (self.reason == Reason::None) == self.prepared.is_some()
                    && self.prepared.as_ref().is_none_or(|v| {
                        v.valid()
                            && v.target == request.target
                            && self.configuration.as_ref().is_some_and(|c| {
                                c.saved_config == Fingerprint::from(v.files[0].after.as_bytes())
                            })
                    })
            }
            Kind::Pending => {
                self.prepared.is_none()
                    && self.publication.is_none()
                    && self.configuration.is_none()
                    && self.reason == Reason::None
                    && self.pending.as_ref().is_some_and(|v| {
                        v.len() <= 64
                            && v.iter()
                                .all(|p| p.valid() && p.summary.target.same_scope(&request.target))
                            && {
                                let mut ids = std::collections::BTreeSet::new();
                                v.iter().all(|p| ids.insert(&p.summary.target.marker))
                            }
                    })
            }
            Kind::Publish | Kind::Reconcile => {
                self.prepared.is_none()
                    && self.pending.is_none()
                    && self
                        .publication
                        .as_ref()
                        .map_or(self.reason != Reason::None, |v| {
                            if v.reason != self.reason
                                || v.control != self.control
                                || !v.control.valid()
                                || v.pull.as_ref().is_some_and(|p| !p.valid(&request.target))
                            {
                                return false;
                            }
                            if self.kind == Kind::Publish {
                                let (Some(claimed), Some(confirmed)) = (&v.claimed, &v.confirmed)
                                else {
                                    return false;
                                };
                                if !progress(claimed, confirmed)
                                    || confirmed.get(&Step::Tree).is_some_and(|tree| {
                                        request
                                            .prepared
                                            .as_ref()
                                            .is_none_or(|p| &p.desired_tree != tree)
                                    })
                                {
                                    return false;
                                }
                                match v.effect {
                                    Effect::NotSent => {
                                        claimed.is_empty()
                                            && confirmed.is_empty()
                                            && v.pull.is_none()
                                            && self.reason != Reason::None
                                    }
                                    Effect::PotentiallyApplied => {
                                        !claimed.is_empty()
                                            && v.pull.is_none()
                                            && self.reason != Reason::None
                                    }
                                    Effect::DraftPrObserved => {
                                        self.reason == Reason::None
                                            && claimed == &STEPS
                                            && confirmed.len() == 4
                                            && v.pull.as_ref().is_some_and(|p| {
                                                Some(&p.commit) == confirmed.get(&Step::Commit)
                                                    && Some(&p.number) == confirmed.get(&Step::Pull)
                                            })
                                    }
                                    _ => false,
                                }
                            } else {
                                v.claimed.is_none()
                                    && v.confirmed.is_none()
                                    && match v.effect {
                                        Effect::Unresolved | Effect::BranchObserved => {
                                            v.pull.is_none() && self.reason != Reason::None
                                        }
                                        Effect::DraftPrObserved => {
                                            v.pull.is_some() && self.reason == Reason::None
                                        }
                                        _ => false,
                                    }
                            }
                        })
            }
        }
    }
}
pub(crate) fn decode_reply(id: &str, raw: &[u8], request: &Request) -> Result<Reply, BridgeError> {
    let value = frame(raw, RESPONSE_LIMIT, 20000)?;
    if let Some(publication) = value
        .get("result")
        .and_then(|v| v.get("publication"))
        .filter(|v| !v.is_null())
    {
        // Missing progress is allowed only on reconcile; explicit null is not
        // absence, and can never erase the durable publish write claims.
        if ["claimed", "confirmed"]
            .iter()
            .any(|k| publication.get(*k).is_some_and(Value::is_null))
        {
            return Err(BridgeError::protocol());
        }
    }
    let reply: Reply = serde_json::from_value(value).map_err(|_| BridgeError::protocol())?;
    if reply.protocol != PROTOCOL
        || reply.id != id
        || !request.valid()
        || !reply.result.valid(request)
    {
        return Err(BridgeError::protocol());
    }
    Ok(reply)
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Running,
    Stopping,
    Settled,
    CleanupUnknown,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operation {
    pub(crate) id: String,
    pub(crate) kind: Kind,
    pub(crate) phase: Phase,
    pub(crate) reason: Reason,
    pub(crate) effect: Effect,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConsentView {
    pub(crate) id: String,
    pub(crate) expires_at: String,
    pub(crate) prepared: Prepared,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32,
    pub(crate) revision: u32,
    pub(crate) session_id: Option<String>,
    pub(crate) available: bool,
    pub(crate) reason: Reason,
    pub(crate) operation: Option<Operation>,
    pub(crate) consent: Option<ConsentView>,
    pub(crate) pending: Vec<Pending>,
    pub(crate) pull: Option<Pull>,
}
impl Status {
    pub(crate) fn fits(&self) -> bool {
        serde_json::to_vec(self).is_ok_and(|v| v.len() <= RESPONSE_LIMIT)
    }
}

fn strings(values: &[&String]) -> Option<usize> {
    values
        .iter()
        .try_fold(0usize, |n, v| n.checked_add(v.capacity()))
}
impl Target {
    fn heap(&self) -> Option<usize> {
        strings(&[
            &self.project_binding,
            &self.repository,
            &self.account_id,
            &self.repository_id,
            &self.base,
            &self.tooling_repository,
            &self.tooling_sha,
            &self.marker,
        ])
    }
}
impl Source {
    fn heap(&self) -> Option<usize> {
        strings(&[
            &self.root,
            &self.root_identity.device,
            &self.root_identity.inode,
        ])
    }
}
impl Prepared {
    pub(crate) fn heap(&self) -> Option<usize> {
        let mut n = self
            .target
            .heap()?
            .checked_add(strings(&[
                &self.protocol,
                &self.base_commit,
                &self.base_tree,
                &self.desired_tree,
                &self.head,
                &self.confirmation,
            ])?)?
            .checked_add(
                self.files
                    .capacity()
                    .checked_mul(std::mem::size_of::<ReviewFile>())?,
            )?;
        for f in &self.files {
            n = n
                .checked_add(strings(&[&f.path, &f.after])?)?
                .checked_add(f.before.as_ref().map_or(0, String::capacity))?;
        }
        Some(n)
    }
}
impl Summary {
    fn heap(&self) -> Option<usize> {
        let mut n = self
            .target
            .heap()?
            .checked_add(strings(&[
                &self.protocol,
                &self.base_commit,
                &self.base_tree,
                &self.desired_tree,
            ])?)?
            .checked_add(
                self.files
                    .capacity()
                    .checked_mul(std::mem::size_of::<FileIdentity>())?,
            )?;
        for f in &self.files {
            n = n
                .checked_add(strings(&[&f.path, &f.after.sha256])?)?
                .checked_add(f.before.as_ref().map_or(0, |v| v.sha256.capacity()))?;
        }
        Some(n)
    }
}
impl Pending {
    fn heap(&self) -> Option<usize> {
        let mut n = self.summary.heap()?.checked_add(
            self.claimed
                .capacity()
                .checked_mul(std::mem::size_of::<Step>())?,
        )?;
        // At most four map entries; includes conservative B-tree node storage.
        n = n.checked_add(self.confirmed.len().checked_mul(512)?)?;
        for v in self.confirmed.values() {
            n = n.checked_add(v.capacity())?;
        }
        Some(n)
    }
}
impl Pull {
    fn heap(&self) -> Option<usize> {
        strings(&[&self.number, &self.url, &self.commit])
    }
}
impl Request {
    pub(crate) fn heap(&self) -> Option<usize> {
        self.target
            .heap()?
            .checked_add(self.source.as_ref().map_or(Some(0), Source::heap)?)?
            .checked_add(self.home.as_ref().map_or(0, String::capacity))?
            .checked_add(self.prepared.as_ref().map_or(Some(0), Prepared::heap)?)
    }
}
impl Status {
    pub(crate) fn heap(&self) -> Option<usize> {
        let mut n = self
            .session_id
            .as_ref()
            .map_or(0, String::capacity)
            .checked_add(self.operation.as_ref().map_or(0, |v| v.id.capacity()))?
            .checked_add(
                self.pending
                    .capacity()
                    .checked_mul(std::mem::size_of::<Pending>())?,
            )?
            .checked_add(self.pull.as_ref().map_or(Some(0), Pull::heap)?)?;
        if let Some(v) = &self.consent {
            n = n
                .checked_add(strings(&[&v.id, &v.expires_at])?)?
                .checked_add(v.prepared.heap()?)?;
        }
        for v in &self.pending {
            n = n.checked_add(v.heap()?)?;
        }
        Some(n)
    }
}
impl Reply {
    pub(crate) fn heap(&self) -> Option<usize> {
        let mut n = strings(&[&self.protocol, &self.id])?.checked_add(
            self.result
                .prepared
                .as_ref()
                .map_or(Some(0), Prepared::heap)?,
        )?;
        if let Some(rows) = &self.result.pending {
            n = n.checked_add(
                rows.capacity()
                    .checked_mul(std::mem::size_of::<Pending>())?,
            )?;
            for v in rows {
                n = n.checked_add(v.heap()?)?;
            }
        }
        if let Some(v) = &self.result.configuration {
            n = n.checked_add(strings(&[
                &v.saved_config.sha256,
                &v.canonical_config.sha256,
            ])?)?;
        }
        if let Some(v) = &self.result.publication {
            n = n.checked_add(v.pull.as_ref().map_or(Some(0), Pull::heap)?)?;
            if let Some(rows) = &v.claimed {
                n = n.checked_add(rows.capacity().checked_mul(std::mem::size_of::<Step>())?)?;
            }
            if let Some(rows) = &v.confirmed {
                n = n.checked_add(rows.len().checked_mul(512)?)?;
                for v in rows.values() {
                    n = n.checked_add(v.capacity())?;
                }
            }
            n = n.checked_add(
                v.control
                    .credential_expires_at
                    .as_ref()
                    .map_or(0, String::capacity),
            )?;
        }
        n.checked_add(
            self.result
                .control
                .credential_expires_at
                .as_ref()
                .map_or(0, String::capacity),
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrepareArgs {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
    pub(crate) base: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublishArgs {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) consent_id: String,
    pub(crate) confirm: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingArgs {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReconcileArgs {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) marker: String,
}
pub(crate) enum Command {
    Status,
    Prepare(PrepareArgs),
    Publish(PublishArgs),
    Pending(PendingArgs),
    Reconcile(ReconcileArgs),
    Discard(crate::github_setup_protocol::DiscardArgs),
    Cancel(crate::github_setup_protocol::CancelArgs),
}
pub(crate) fn decode_command(name: &str, value: &Value) -> Result<Command, BridgeError> {
    if !value.is_object() || !bounds(value, 4096, 64, 4) {
        return Err(BridgeError::invalid());
    }
    fn read<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, BridgeError> {
        serde_json::from_value(v.clone()).map_err(|_| BridgeError::invalid())
    }
    let revision = |v: u32| v > 0 && v <= LAST_REVISION;
    Ok(match name {
        "github_setup_publication_status" if value.as_object().is_some_and(|v| v.is_empty()) => {
            Command::Status
        }
        "github_setup_publication_prepare" => {
            let v: PrepareArgs = read(value)?;
            if !valid_id(&v.session_id)
                || !revision(v.expected_revision)
                || !revision(v.expected_connection_revision)
                || !branch(&v.base)
            {
                return Err(BridgeError::invalid());
            }
            Command::Prepare(v)
        }
        "github_setup_publication_publish" => {
            let v: PublishArgs = read(value)?;
            if !valid_id(&v.session_id)
                || !revision(v.expected_revision)
                || !hex(&v.consent_id, 32)
                || !v.confirm
            {
                return Err(BridgeError::invalid());
            }
            Command::Publish(v)
        }
        "github_setup_publication_pending" => {
            let v: PendingArgs = read(value)?;
            if !valid_id(&v.session_id)
                || !revision(v.expected_revision)
                || !revision(v.expected_connection_revision)
            {
                return Err(BridgeError::invalid());
            }
            Command::Pending(v)
        }
        "github_setup_publication_reconcile" => {
            let v: ReconcileArgs = read(value)?;
            if !valid_id(&v.session_id) || !revision(v.expected_revision) || !hex(&v.marker, 32) {
                return Err(BridgeError::invalid());
            }
            Command::Reconcile(v)
        }
        "github_setup_publication_discard" => {
            let v: crate::github_setup_protocol::DiscardArgs = read(value)?;
            if !valid_id(&v.session_id) || !revision(v.expected_revision) || !hex(&v.consent_id, 32)
            {
                return Err(BridgeError::invalid());
            }
            Command::Discard(v)
        }
        "github_setup_publication_cancel" => {
            let v: crate::github_setup_protocol::CancelArgs = read(value)?;
            if !valid_id(&v.operation_id) {
                return Err(BridgeError::invalid());
            }
            Command::Cancel(v)
        }
        _ => return Err(BridgeError::invalid()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target() -> Target {
        Target {
            project_binding: "a".repeat(64),
            repository: "owner/repo".into(),
            account_id: "1".into(),
            repository_id: "2".into(),
            base: "release/candidate".into(),
            tooling_repository: TOOLING_REPOSITORY.into(),
            tooling_sha: "b".repeat(40),
            marker: "c".repeat(32),
        }
    }
    fn source() -> Source {
        Source {
            root: "/inert/project".into(),
            root_identity: SecretRootIdentity {
                device: "1".into(),
                inode: "2".into(),
                mode: 0o40700,
                uid: 1000,
                gid: 1000,
            },
        }
    }
    fn prepared() -> Prepared {
        let target = target();
        Prepared {
            protocol: PROTOCOL.into(),
            head: target.head(),
            target,
            base_commit: "d".repeat(40),
            base_tree: "e".repeat(40),
            desired_tree: "f".repeat(40),
            confirmation: CONFIRMATION.into(),
            files: PATHS
                .iter()
                .map(|path| ReviewFile {
                    path: (*path).into(),
                    before: None,
                    after: "bounded fixture DATA".into(),
                })
                .collect(),
        }
    }
    fn request(kind: Kind) -> Request {
        Request {
            kind,
            target: target(),
            source: matches!(kind, Kind::Prepare | Kind::Publish).then(source),
            home: (kind != Kind::Prepare).then(|| "/inert/home".into()),
            prepared: (kind == Kind::Publish).then(prepared),
        }
    }
    fn control() -> Value {
        serde_json::json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false})
    }
    fn response() -> Value {
        let prepared = prepared();
        let saved = Fingerprint::from(prepared.files[0].after.as_bytes());
        serde_json::json!({"protocol":PROTOCOL,"id":"fixture","result":{"schemaVersion":1,"kind":"prepare","reason":"none",
            "prepared":prepared,"publication":null,"pending":null,"configuration":{"savedConfig":saved,"canonicalConfig":saved},"control":control()}})
    }
    fn wire(value: &Value) -> Vec<u8> {
        let mut raw = serde_json::to_vec(value).unwrap();
        raw.push(b'\n');
        raw
    }
    #[test]
    fn publication_commands_never_accept_paths_bytes_tokens_or_mutating_recovery() {
        let value = serde_json::json!({"sessionId":"session-1","expectedRevision":1,"expectedConnectionRevision":1,"base":"main"});
        assert!(decode_command("github_setup_publication_prepare", &value).is_ok());
        for key in ["root", "token", "prepared", "source", "sha", "force"] {
            let mut changed = value.clone();
            changed[key] = Value::String("untrusted".into());
            assert!(decode_command("github_setup_publication_prepare", &changed).is_err());
        }
        assert!(decode_command("github_setup_publication_merge", &value).is_err());
        let mut changed = value;
        changed["expectedRevision"] = Value::Bool(true);
        assert!(decode_command("github_setup_publication_prepare", &changed).is_err());
    }
    #[test]
    fn publication_initial_go_exact_review_and_pending_has_no_token() {
        for kind in [Kind::Prepare, Kind::Publish, Kind::Pending, Kind::Reconcile] {
            let request = request(kind);
            assert!(request.valid());
            let initial = encode_initial("fixture", &request).unwrap();
            let expected = digest(&initial);
            let value: Value = serde_json::from_slice(&initial).unwrap();
            assert_eq!(value["action"]["source"].get("draft"), None);
            let token = (kind != Kind::Pending).then_some("INERT_TOKEN");
            let go = encode_go("fixture", &expected, token, &request).unwrap();
            let parsed: Value = serde_json::from_slice(&go).unwrap();
            assert_eq!(parsed["go"]["requestSha256"], expected);
            assert_eq!(
                value["action"]["preparedSha256"],
                request
                    .prepared
                    .as_ref()
                    .map(|v| Value::String(v.sha256().unwrap()))
                    .unwrap_or(Value::Null)
            );
            assert!(encode_go(
                "fixture",
                &expected,
                if token.is_some() {
                    None
                } else {
                    Some("INERT_TOKEN")
                },
                &request
            )
            .is_err());
        }
    }
    #[test]
    fn publication_ready_and_reply_refuse_duplicate_positional_partial_or_wrong_capture() {
        let ready = serde_json::json!({"protocol":PROTOCOL,"id":"fixture","ready":{"requestSha256":"a".repeat(64)}});
        assert!(decode_ready(&wire(&ready), "fixture", &"a".repeat(64)).is_ok());
        assert!(decode_ready(&wire(&ready), "fixture", &"b".repeat(64)).is_err());
        let request = request(Kind::Prepare);
        let value = response();
        assert!(decode_reply("fixture", &wire(&value), &request).is_ok());
        for (field, replacement) in [
            ("prepared", Value::Array(vec![])),
            ("configuration", Value::Array(vec![])),
            ("control", Value::Array(vec![])),
        ] {
            let mut bad = value.clone();
            bad["result"][field] = replacement;
            assert!(decode_reply("fixture", &wire(&bad), &request).is_err());
        }
        let mut bad = value.clone();
        bad["result"]["prepared"]["files"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(decode_reply("fixture", &wire(&bad), &request).is_err());
        let mut bad = value.clone();
        bad["result"]["configuration"]["savedConfig"]["sha256"] = Value::String("0".repeat(64));
        assert!(decode_reply("fixture", &wire(&bad), &request).is_err());
        let mut bad = value;
        bad["result"]["prepared"]["files"][4]["path"] =
            Value::String("release/version.properties".into());
        assert!(decode_reply("fixture", &wire(&bad), &request).is_err());
        assert!(decode_reply("fixture", b"{\"protocol\":1,\"protocol\":2}\n", &request).is_err());
    }
    #[test]
    fn publication_durable_phase_prefix_never_grants_replayed_writes() {
        let prepared = prepared();
        let mut record = Pending {
            summary: prepared.summary(),
            claimed: vec![Step::Tree],
            confirmed: BTreeMap::new(),
        };
        assert!(record.valid());
        record.claimed.push(Step::Commit);
        assert!(!record.valid());
        record
            .confirmed
            .insert(Step::Tree, prepared.desired_tree.clone());
        assert!(record.valid());
        record.confirmed.insert(Step::Commit, "7".repeat(40));
        record.claimed.push(Step::Branch);
        record.confirmed.insert(Step::Branch, "8".repeat(40));
        assert!(!record.valid());
        record.confirmed.insert(Step::Branch, "7".repeat(40));
        assert!(record.valid());
        record.summary.files[0].after.bytes = 0;
        assert!(!record.valid());
    }
    #[test]
    fn publication_positive_effect_requires_complete_matching_claims_and_pull() {
        let request = request(Kind::Publish);
        let prepared = request.prepared.as_ref().unwrap();
        let mut value = serde_json::json!({"protocol":PROTOCOL,"id":"fixture","result":{"schemaVersion":1,"kind":"publish","reason":"none",
            "prepared":null,"pending":null,"configuration":null,"control":control(),"publication":{"effect":"draft-pr-observed","reason":"none",
            "claimed":["tree","commit","branch","pull"],"confirmed":{"tree":prepared.desired_tree,"commit":"7".repeat(40),"branch":"7".repeat(40),"pull":"8"},
            "pull":{"number":"8","commit":"7".repeat(40),"url":"https://github.com/owner/repo/pull/8"},"control":control()}}});
        assert!(decode_reply("fixture", &wire(&value), &request).is_ok());
        value["result"]["publication"]["confirmed"]["branch"] = Value::String("9".repeat(40));
        assert!(decode_reply("fixture", &wire(&value), &request).is_err());
        value["result"]["publication"]["confirmed"] = Value::Null;
        assert!(decode_reply("fixture", &wire(&value), &request).is_err());
    }
}
