//! Fixed hosted known-edit cleanup DATA on the existing GitHub owner.
//! A dispatch receipt or later journal observation is never cleanup proof.
use crate::{
    error::BridgeError,
    github_connection_protocol::{bounds, nullable, numeric_id, GitHubReadControl},
    github_preflight_protocol::{branch, hex},
    github_repository_create_protocol::{coordinate, login},
    protocol::{strict_json, valid_id},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub(crate) use crate::github_publication_protocol::Source;
pub(crate) use crate::version_enrollment_protocol::{Authority, Checkpoint, Version};
pub(crate) const PROTOCOL: &str = "mrk-github-play-cleanup/1";
pub(crate) const EVENT: &str = "github-play-cleanup-status";
pub(crate) const INITIAL_LIMIT: usize = 8192;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const GO_LIMIT: usize = 16 * 1024;
pub(crate) const PREPARED_LIMIT: usize = 4096;
pub(crate) const RESPONSE_LIMIT: usize = 192 * 1024;
pub(crate) const RETAINED_LIMIT: usize = 8 * 1024 * 1024;
// Serial HTTP parsing + complete hosted ledger/envelope/local-record DATA.
// The prospective 8,000-token guard runs BEFORE JSON decoding, including
// embedded Contents documents. This is owned-backing arithmetic, not RSS.
pub(crate) const REMOTE_WORK_BYTES: usize = 16 * 1024 * 1024;
// The complete shared Document has its own 64-MiB ceiling. Cleanup keeps its
// existing 16+16+8-MiB work reservation separately: at most 104 MiB of owned
// backing, not RSS, extra credential capacity, or credit from unused work.
pub(crate) const DOCUMENT_LIMIT: usize = 64 * 1024 * 1024;
pub(crate) const SESSION_LIMIT: usize = DOCUMENT_LIMIT
    + crate::github_setup_protocol::SECRET_CONFIGURATION_WORK_BYTES
    + REMOTE_WORK_BYTES
    + RETAINED_LIMIT;
pub(crate) fn admission_bytes(retained_document: usize) -> Option<usize> {
    if retained_document > DOCUMENT_LIMIT {
        return None;
    }
    retained_document
        .checked_add(crate::github_setup_protocol::SECRET_CONFIGURATION_WORK_BYTES)?
        .checked_add(REMOTE_WORK_BYTES)?
        .checked_add(RETAINED_LIMIT)
        .filter(|n| *n <= SESSION_LIMIT)
}
pub(crate) const LAST_REVISION: u32 = u32::MAX - 1;

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, BridgeError> {
    serde_json::to_value(value)
        .and_then(|v| serde_json::to_vec(&v))
        .map_err(|_| BridgeError::protocol())
}
pub(crate) fn configured() -> bool {
    crate::github_release_protocol::TOOLING_SHA.is_some_and(|v| hex(v, 40))
        && crate::github_release_protocol::CANDIDATE_SHA256.is_some_and(|v| hex(v, 64))
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    Prepare,
    Dispatch,
    Pending,
    Observe,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    InvalidInput,
    TargetChanged,
    SelectionChanged,
    SourceChanged,
    SourceTreeUnavailable,
    SourceUnsupported,
    ConfigurationInvalid,
    CallerMismatch,
    WorkflowUnavailable,
    PermissionUnconfirmed,
    CounterUnavailable,
    ProtectionUnsupported,
    AuthorityChanged,
    AuthorityRewound,
    LedgerInvalid,
    JournalInvalid,
    CleanupUnavailable,
    CleanupClaimed,
    ReviewChanged,
    Unauthorized,
    Forbidden,
    NotFoundOrInaccessible,
    RateLimited,
    NetworkUnavailable,
    TlsFailed,
    ResponseInvalid,
    ResponseLimit,
    Expired,
    Cancelled,
    JournalUnavailable,
    PreviousAttempt,
    JournalFull,
    Unresolved,
    ResourcesUnavailable,
    RuntimeUnavailable,
    Unqualified,
    PublisherUnconfigured,
    NotConnected,
    Busy,
    CleanupUnknown,
    ConsentExpired,
}
impl Reason {
    fn core(self) -> bool {
        !matches!(
            self,
            Self::ResourcesUnavailable
                | Self::RuntimeUnavailable
                | Self::Unqualified
                | Self::PublisherUnconfigured
                | Self::NotConnected
                | Self::Busy
                | Self::CleanupUnknown
                | Self::ConsentExpired
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Effect {
    None,
    NotSent,
    PotentiallyApplied,
    AcknowledgedUnconfirmed,
    Unresolved,
    ObservedUnconfirmed,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform {
    Android,
    Both,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Scope {
    pub(crate) project_binding: String,
    pub(crate) repository: String,
    pub(crate) account_id: String,
    pub(crate) repository_id: String,
}
impl Scope {
    fn valid(&self) -> bool {
        hex(&self.project_binding, 64)
            && coordinate(&self.repository)
            && numeric_id(&self.account_id)
            && numeric_id(&self.repository_id)
    }
    fn heap(&self) -> Option<usize> {
        strings(&[
            &self.project_binding,
            &self.repository,
            &self.account_id,
            &self.repository_id,
        ])
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) scope: Scope,
    pub(crate) tooling_repository: String,
    pub(crate) tooling_sha: String,
    pub(crate) marker: String,
}
impl Target {
    pub(crate) fn valid(&self) -> bool {
        self.scope.valid()
            && self.tooling_repository == crate::github_release_protocol::TOOLING_REPOSITORY
            && hex(&self.tooling_sha, 40)
            && hex(&self.marker, 32)
    }
    pub(crate) fn publisher_bound(&self) -> bool {
        self.valid()
            && Some(self.tooling_sha.as_str()) == crate::github_release_protocol::TOOLING_SHA
    }
    pub(crate) fn same_scope(&self, other: &Self) -> bool {
        self.scope.project_binding == other.scope.project_binding
            && self.scope.account_id == other.scope.account_id
            && self.scope.repository_id == other.scope.repository_id
            && self
                .scope
                .repository
                .eq_ignore_ascii_case(&other.scope.repository)
    }
    fn heap(&self) -> Option<usize> {
        self.scope.heap()?.checked_add(strings(&[
            &self.tooling_repository,
            &self.tooling_sha,
            &self.marker,
        ])?)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OriginalSource {
    pub(crate) commit: String,
    pub(crate) tree: String,
    #[serde(rename = "ref")]
    pub(crate) source_ref: String,
    pub(crate) configuration_sha256: String,
    pub(crate) version_sha256: String,
}
impl OriginalSource {
    fn valid(&self) -> bool {
        hex(&self.commit, 40)
            && hex(&self.tree, 40)
            && self
                .source_ref
                .strip_prefix("refs/heads/")
                .is_some_and(branch)
            && hex(&self.configuration_sha256, 64)
            && hex(&self.version_sha256, 64)
    }
    fn heap(&self) -> Option<usize> {
        strings(&[
            &self.commit,
            &self.tree,
            &self.source_ref,
            &self.configuration_sha256,
            &self.version_sha256,
        ])
    }
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(n, b)| match n {
            8 | 13 | 18 | 23 => b == b'-',
            14 => b == b'4',
            19 => b"89ab".contains(&b),
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Candidate {
    pub(crate) candidate_id: String,
    pub(crate) attempt_id: String,
    pub(crate) request_sha256: String,
    pub(crate) local_project_id: String,
    pub(crate) platform: Platform,
    pub(crate) source: OriginalSource,
    pub(crate) identity_revision: String,
    pub(crate) base_version: Version,
    pub(crate) capsule_sha256: String,
}
impl Candidate {
    fn valid(&self) -> bool {
        uuid(&self.candidate_id)
            && uuid(&self.attempt_id)
            && hex(&self.request_sha256, 64)
            && hex(&self.local_project_id, 32)
            && self.local_project_id.bytes().any(|b| b != b'0')
            && self.source.valid()
            && hex(&self.identity_revision, 64)
            && hex(&self.capsule_sha256, 64)
    }
    fn heap(&self) -> Option<usize> {
        strings(&[
            &self.candidate_id,
            &self.attempt_id,
            &self.request_sha256,
            &self.local_project_id,
            &self.identity_revision,
            &self.base_version.name,
            &self.capsule_sha256,
        ])?
        .checked_add(self.source.heap()?)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepared {
    pub(crate) target: Target,
    pub(crate) account_login: String,
    pub(crate) branch: String,
    pub(crate) source_sha: String,
    pub(crate) source_tree: String,
    pub(crate) saved_config_sha256: String,
    pub(crate) workflow_id: String,
    pub(crate) caller_sha256: String,
    pub(crate) authority: Authority,
    pub(crate) checkpoint: Checkpoint,
    pub(crate) ledger_blob: String,
    pub(crate) journal_blob: String,
    pub(crate) journal_sha256: String,
    pub(crate) journal_revision: u64,
    pub(crate) candidate: Candidate,
    pub(crate) confirmation: String,
}
impl Prepared {
    fn confirmation(&self) -> String {
        format!("Dispatch one hosted Play edit cleanup for candidate {} in {}? This is nonpublishing but mutating: the protected workflow may decrypt its retained edit ID, consume its one-use cleanup claim and delete that Play edit. It does not reserve a version or build, sign or release. The configured branch {} is mutable; authorized writers can replace its workflow after review. Its actual dispatch head may differ from the reviewed head; the workflow must separately validate the original candidate source. A dispatch acknowledgement does not prove cleanup or identify a run. Stopping cannot undo a sent request.", self.candidate.candidate_id, self.target.scope.repository, self.branch)
    }
    pub(crate) fn valid(&self) -> bool {
        // Reuse the existing closed authority/checkpoint/version shape parser.
        // An Offer value here is DATA, never native enrollment or Store proof.
        let offer = crate::version_enrollment_protocol::Offer {
            authority: self.authority.clone(),
            checkpoint: self.checkpoint.clone(),
            blob: self.ledger_blob.clone(),
            version: self.candidate.base_version.clone(),
        };
        self.target.valid()
            && self.candidate.valid()
            && offer.valid()
            && login(&self.account_login)
            && branch(&self.branch)
            && self.candidate.source.source_ref == format!("refs/heads/{}", self.branch)
            && self
                .authority
                .repository
                .eq_ignore_ascii_case(&self.target.scope.repository)
            && self.authority.repository_id == self.target.scope.repository_id
            && [
                &self.source_sha,
                &self.source_tree,
                &self.ledger_blob,
                &self.journal_blob,
            ]
            .iter()
            .all(|v| hex(v, 40))
            && [
                &self.saved_config_sha256,
                &self.caller_sha256,
                &self.journal_sha256,
            ]
            .iter()
            .all(|v| hex(v, 64))
            && numeric_id(&self.workflow_id)
            && self.journal_revision > 0
            && self.confirmation == self.confirmation()
            && canonical(self).is_ok_and(|v| v.len() <= PREPARED_LIMIT)
    }
    pub(crate) fn publisher_bound(&self) -> bool {
        self.valid()
            && self.target.publisher_bound()
            && Some(self.caller_sha256.as_str()) == crate::github_release_protocol::CANDIDATE_SHA256
    }
    pub(crate) fn digest(&self) -> Result<String, BridgeError> {
        canonical(self).map(|v| format!("{:x}", Sha256::digest(v)))
    }
    pub(crate) fn once_key(&self) -> (&str, &str, &str, &str, &str, &str) {
        (
            &self.target.scope.repository_id,
            &self.authority.project_id,
            &self.authority.ledger_id,
            &self.authority.genesis_sha256,
            &self.candidate.candidate_id,
            &self.candidate.attempt_id,
        )
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.target
            .heap()?
            .checked_add(self.candidate.heap()?)?
            .checked_add(strings(&[
                &self.account_login,
                &self.branch,
                &self.source_sha,
                &self.source_tree,
                &self.saved_config_sha256,
                &self.workflow_id,
                &self.caller_sha256,
                &self.authority.project_id,
                &self.authority.repository,
                &self.authority.repository_id,
                &self.authority.ledger_id,
                &self.authority.genesis_sha256,
                &self.checkpoint.head_sha256,
                &self.checkpoint.commit,
                &self.ledger_blob,
                &self.journal_blob,
                &self.journal_sha256,
                &self.confirmation,
            ])?)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pending {
    pub(crate) prepared: Prepared,
    pub(crate) claimed: bool,
    pub(crate) acknowledged: bool,
}
impl Pending {
    fn valid(&self) -> bool {
        self.prepared.valid() && (!self.acknowledged || self.claimed)
    }
    fn heap(&self) -> Option<usize> {
        self.prepared.heap()
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
            && matches!(self.kind, Kind::Prepare | Kind::Dispatch) == self.source.is_some()
            && self.source.as_ref().is_none_or(Source::valid)
            && (self.kind == Kind::Prepare) == self.home.is_none()
            && self.home.as_ref().is_none_or(|v| {
                v.starts_with('/')
                    && v.len() <= 3968
                    && !v.chars().any(char::is_control)
                    && v.split('/')
                        .skip(1)
                        .all(|s| !s.is_empty() && s != "." && s != "..")
            })
            && matches!(self.kind, Kind::Dispatch | Kind::Observe) == self.prepared.is_some()
            && self
                .prepared
                .as_ref()
                .is_none_or(|v| v.valid() && v.target == self.target)
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.target
            .heap()?
            .checked_add(self.home.as_ref().map_or(0, String::capacity))?
            .checked_add(self.source.as_ref().map_or(Some(0), |s| {
                strings(&[&s.root, &s.root_identity.device, &s.root_identity.inode])
            })?)?
            .checked_add(self.prepared.as_ref().map_or(Some(0), Prepared::heap)?)
    }
}
fn frame(raw: &[u8], limit: usize, nodes: usize) -> Result<Value, BridgeError> {
    if raw.len() < 3 || raw.len() > limit || !raw.ends_with(b"\n") {
        return Err(BridgeError::protocol());
    }
    let body = &raw[..raw.len() - 1];
    if body.first() != Some(&b'{')
        || body.last() != Some(&b'}')
        || body.iter().any(|b| matches!(b, b'\r' | b'\n'))
    {
        return Err(BridgeError::protocol());
    }
    let value = strict_json(body)?;
    fn shape(v: &Value, key: &str) -> bool {
        match v {
            Value::Array(rows) => key == "pending" && rows.iter().all(|v| shape(v, "")),
            Value::Object(o) => o.iter().all(|(k, v)| shape(v, k)),
            _ => true,
        }
    }
    if !bounds(&value, limit, nodes, 12) || !shape(&value, "") {
        return Err(BridgeError::protocol());
    }
    Ok(value)
}
pub(crate) fn encode_initial(id: &str, r: &Request) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !r.valid() {
        return Err(BridgeError::invalid());
    }
    let digest = r.prepared.as_ref().map(Prepared::digest).transpose()?;
    let mut bytes = canonical(&serde_json::json!({"protocol":PROTOCOL,"id":id,"action":{
        "kind":r.kind,"target":r.target,"source":r.source,"home":r.home,"preparedSha256":digest}}))?;
    bytes.push(b'\n');
    if bytes.len() > INITIAL_LIMIT {
        return Err(BridgeError::invalid());
    }
    Ok(bytes)
}
pub(crate) fn decode_ready(raw: &[u8], id: &str, digest: &str) -> Result<(), BridgeError> {
    if !valid_id(id)
        || !hex(digest, 64)
        || frame(raw, READY_LIMIT, 32)?
            != serde_json::json!({"protocol":PROTOCOL,"id":id,"ready":{"requestSha256":digest}})
    {
        return Err(BridgeError::protocol());
    }
    Ok(())
}
struct PrivateGo(zeroize::Zeroizing<Vec<u8>>);
impl Write for PrivateGo {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.len() > GO_LIMIT.saturating_sub(self.0.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private frame bound",
            ));
        }
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode_go(
    id: &str,
    digest: &str,
    token: Option<&str>,
    r: &Request,
) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id)
        || !hex(digest, 64)
        || !r.valid()
        || (r.kind == Kind::Pending) != token.is_none()
        || token.is_some_and(|t| {
            t.is_empty() || t.len() > 4096 || !t.bytes().all(|b| (0x21..=0x7e).contains(&b))
        })
    {
        return Err(BridgeError::invalid());
    }
    let mut w = PrivateGo(zeroize::Zeroizing::new(Vec::with_capacity(GO_LIMIT)));
    let write = (|| -> Result<(), Box<dyn std::error::Error>> {
        w.write_all(b"{\"protocol\":\"mrk-github-play-cleanup/1\",\"id\":")?;
        serde_json::to_writer(&mut w, id)?;
        w.write_all(b",\"go\":{\"requestSha256\":")?;
        serde_json::to_writer(&mut w, digest)?;
        w.write_all(b",\"prepared\":")?;
        serde_json::to_writer(&mut w, &r.prepared)?;
        w.write_all(b",\"token\":")?;
        serde_json::to_writer(&mut w, &token)?;
        w.write_all(b"}}\n")?;
        Ok(())
    })();
    if write.is_err() {
        return Err(BridgeError::invalid());
    }
    Ok(std::mem::take(&mut *w.0))
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PendingTuple {
    SameUnclaimed,
    SameClaimed,
    Different,
    NotPresent,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Observation {
    pub(crate) counter_commit: String,
    pub(crate) journal_sha256: String,
    pub(crate) journal_revision: u64,
    pub(crate) pending_tuple: PendingTuple,
    assurance: String,
}
impl Observation {
    fn valid(&self) -> bool {
        hex(&self.counter_commit, 40)
            && hex(&self.journal_sha256, 64)
            && self.journal_revision > 0
            && self.assurance == "later-journal-read-not-cleanup-proof"
    }
    fn heap(&self) -> Option<usize> {
        strings(&[&self.counter_commit, &self.journal_sha256, &self.assurance])
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cleanup {
    pub(crate) effect: Effect,
    pub(crate) reason: Reason,
    pub(crate) claimed: bool,
    pub(crate) acknowledged: bool,
    #[serde(deserialize_with = "nullable")]
    pub(crate) observed: Option<Observation>,
    pub(crate) control: GitHubReadControl,
}
impl Cleanup {
    fn valid(&self, r: &Request) -> bool {
        if r.prepared.is_none()
            || !self.control.valid()
            || !self.reason.core()
            || self.acknowledged && !self.claimed
            || self.observed.as_ref().is_some_and(|v| !v.valid())
        {
            return false;
        }
        match self.effect {
            Effect::NotSent => {
                r.kind == Kind::Dispatch
                    && !self.claimed
                    && !self.acknowledged
                    && self.observed.is_none()
                    && self.reason != Reason::None
            }
            Effect::PotentiallyApplied => {
                r.kind == Kind::Dispatch
                    && self.claimed
                    && !self.acknowledged
                    && self.observed.is_none()
                    && self.reason != Reason::None
            }
            Effect::AcknowledgedUnconfirmed => {
                r.kind == Kind::Dispatch
                    && self.claimed
                    && self.acknowledged
                    && self.observed.is_none()
            }
            Effect::Unresolved => {
                r.kind == Kind::Observe && self.observed.is_none() && self.reason != Reason::None
            }
            Effect::ObservedUnconfirmed => {
                r.kind == Kind::Observe && self.observed.is_some() && self.reason == Reason::None
            }
            Effect::None => false,
        }
    }
    fn heap(&self) -> Option<usize> {
        self.observed
            .as_ref()
            .map_or(Some(0), Observation::heap)?
            .checked_add(
                self.control
                    .credential_expires_at
                    .as_ref()
                    .map_or(0, String::capacity),
            )
    }
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
    pub(crate) cleanup: Option<Cleanup>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) pending: Option<Vec<Pending>>,
    pub(crate) control: GitHubReadControl,
}
impl ResultData {
    fn valid(&self, r: &Request) -> bool {
        if self.schema_version != 1
            || self.kind != r.kind
            || !self.reason.core()
            || !self.control.valid()
        {
            return false;
        }
        match r.kind {
            Kind::Prepare => {
                self.cleanup.is_none()
                    && self.pending.is_none()
                    && (self.reason == Reason::None) == self.prepared.is_some()
                    && self
                        .prepared
                        .as_ref()
                        .is_none_or(|p| p.valid() && p.target == r.target)
            }
            Kind::Pending => {
                self.cleanup.is_none()
                    && self.prepared.is_none()
                    && (self.reason == Reason::None) == self.pending.is_some()
                    && self.pending.as_ref().is_none_or(|rows| {
                        let mut markers = std::collections::BTreeSet::new();
                        let mut tuples = std::collections::BTreeSet::new();
                        rows.len() <= 32
                            && rows.iter().all(|v| {
                                v.valid()
                                    && v.prepared.target.same_scope(&r.target)
                                    && markers.insert(&v.prepared.target.marker)
                                    && tuples.insert(v.prepared.once_key())
                            })
                    })
            }
            Kind::Dispatch | Kind::Observe => {
                self.prepared.is_none()
                    && self.pending.is_none()
                    && self
                        .cleanup
                        .as_ref()
                        .map_or(self.reason != Reason::None, |v| {
                            v.valid(r) && v.reason == self.reason && v.control == self.control
                        })
            }
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply {
    pub(crate) protocol: String,
    pub(crate) id: String,
    pub(crate) result: ResultData,
}
pub(crate) fn decode_reply(id: &str, raw: &[u8], r: &Request) -> Result<Reply, BridgeError> {
    let reply: Reply = serde_json::from_value(frame(raw, RESPONSE_LIMIT, 8192)?)
        .map_err(|_| BridgeError::protocol())?;
    if reply.protocol != PROTOCOL || reply.id != id || !r.valid() || !reply.result.valid(r) {
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
    pub(crate) project_id: String,
    pub(crate) kind: Kind,
    pub(crate) target: Target,
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
    pub(crate) agent_allowed: bool,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) agent_access: Option<crate::service_play_cleanup_protocol::Access>,
    pub(crate) schema_version: u32,
    pub(crate) revision: u32,
    pub(crate) session_id: Option<String>,
    pub(crate) available: bool,
    pub(crate) reason: Reason,
    pub(crate) operation: Option<Operation>,
    pub(crate) consent: Option<ConsentView>,
    pub(crate) pending: Vec<Pending>,
    pub(crate) observed: Option<Observation>,
    pub(crate) acknowledged: bool,
}
impl Status {
    pub(crate) fn fits(&self) -> bool {
        canonical(self).is_ok_and(|v| v.len() <= RESPONSE_LIMIT)
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        let mut n = self
            .session_id
            .as_ref()
            .map_or(0, String::capacity)
            .checked_add(
                self.pending
                    .capacity()
                    .checked_mul(std::mem::size_of::<Pending>())?,
            )?;
        if let Some(access) = &self.agent_access {
            n = n
                .checked_add(access.project_id.as_str().len())?
                .checked_add(access.service_instance.as_str().len())?
                .checked_add(access.consent_id.as_str().len())?;
        }
        if let Some(v) = &self.operation {
            n = n
                .checked_add(strings(&[&v.id, &v.project_id])?)?
                .checked_add(v.target.heap()?)?;
        }
        if let Some(v) = &self.consent {
            n = n
                .checked_add(strings(&[&v.id, &v.expires_at])?)?
                .checked_add(v.prepared.heap()?)?;
        }
        for row in &self.pending {
            n = n.checked_add(row.heap()?)?;
        }
        n.checked_add(self.observed.as_ref().map_or(Some(0), Observation::heap)?)
    }
}
impl Reply {
    pub(crate) fn heap(&self) -> Option<usize> {
        let mut n = strings(&[&self.id, &self.protocol])?
            .checked_add(
                self.result
                    .prepared
                    .as_ref()
                    .map_or(Some(0), Prepared::heap)?,
            )?
            .checked_add(
                self.result
                    .cleanup
                    .as_ref()
                    .map_or(Some(0), Cleanup::heap)?,
            )?
            .checked_add(
                self.result
                    .control
                    .credential_expires_at
                    .as_ref()
                    .map_or(0, String::capacity),
            )?;
        if let Some(rows) = &self.result.pending {
            n = n.checked_add(
                rows.capacity()
                    .checked_mul(std::mem::size_of::<Pending>())?,
            )?;
            for row in rows {
                n = n.checked_add(row.heap()?)?;
            }
        }
        Some(n)
    }
}
fn strings(values: &[&String]) -> Option<usize> {
    values
        .iter()
        .try_fold(0usize, |n, v| n.checked_add(v.capacity()))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrepareArgs {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
}
pub(crate) type PendingArgs = PrepareArgs;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartArgs {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) consent_id: String,
    pub(crate) confirm: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObserveArgs {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) marker: String,
}
pub(crate) enum Command {
    Status,
    Prepare(PrepareArgs),
    Start(StartArgs),
    AllowAgent(StartArgs),
    Pending(PendingArgs),
    Observe(ObserveArgs),
    Discard(crate::github_setup_protocol::DiscardArgs),
    Cancel(crate::github_setup_protocol::CancelArgs),
}
pub(crate) fn raw_input(_name: &str, bytes: &[u8]) -> Result<Value, BridgeError> {
    if bytes.is_empty() || bytes.len() > 1024 {
        return Err(BridgeError::invalid());
    }
    let value = strict_json(bytes).map_err(|_| BridgeError::invalid())?;
    if !value.is_object() || !bounds(&value, 1024, 48, 4) {
        return Err(BridgeError::invalid());
    }
    Ok(value)
}
pub(crate) fn decode_command(name: &str, value: &Value) -> Result<Command, BridgeError> {
    if !value.is_object() || !bounds(value, 1024, 48, 4) {
        return Err(BridgeError::invalid());
    }
    fn read<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, BridgeError> {
        serde_json::from_value(v.clone()).map_err(|_| BridgeError::invalid())
    }
    let rev = |n: u32| n > 0 && n <= LAST_REVISION;
    Ok(match name {
        "github_play_cleanup_status" if value.as_object().is_some_and(|v| v.is_empty()) => {
            Command::Status
        }
        "github_play_cleanup_prepare" | "github_play_cleanup_pending" => {
            let a: PrepareArgs = read(value)?;
            if !valid_id(&a.session_id)
                || !rev(a.expected_revision)
                || !rev(a.expected_connection_revision)
            {
                return Err(BridgeError::invalid());
            }
            if name.ends_with("prepare") {
                Command::Prepare(a)
            } else {
                Command::Pending(a)
            }
        }
        "github_play_cleanup_start" | "github_play_cleanup_allow_agent" => {
            let a: StartArgs = read(value)?;
            if !valid_id(&a.session_id)
                || !rev(a.expected_revision)
                || !hex(&a.consent_id, 32)
                || !a.confirm
            {
                return Err(BridgeError::invalid());
            }
            if name.ends_with("allow_agent") {
                Command::AllowAgent(a)
            } else {
                Command::Start(a)
            }
        }
        "github_play_cleanup_observe" => {
            let a: ObserveArgs = read(value)?;
            if !valid_id(&a.session_id) || !rev(a.expected_revision) || !hex(&a.marker, 32) {
                return Err(BridgeError::invalid());
            }
            Command::Observe(a)
        }
        "github_play_cleanup_discard" => {
            let a: crate::github_setup_protocol::DiscardArgs = read(value)?;
            if !valid_id(&a.session_id) || !rev(a.expected_revision) || !hex(&a.consent_id, 32) {
                return Err(BridgeError::invalid());
            }
            Command::Discard(a)
        }
        "github_play_cleanup_cancel" => {
            let a: crate::github_setup_protocol::CancelArgs = read(value)?;
            if !valid_id(&a.operation_id) {
                return Err(BridgeError::invalid());
            }
            Command::Cancel(a)
        }
        _ => return Err(BridgeError::invalid()),
    })
}

#[cfg(test)]
#[path = "github_play_cleanup_protocol_tests.rs"]
mod tests;
