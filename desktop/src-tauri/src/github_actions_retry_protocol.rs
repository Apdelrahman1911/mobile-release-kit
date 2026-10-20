//! Closed Actions retry DATA. A run-specific review is not provider CAS or release authority.
use crate::{
    error::BridgeError,
    github_connection_protocol::{bounds, nullable, numeric_id, utc, GitHubReadControl},
    github_preflight_protocol::hex,
    github_repository_create_protocol::{coordinate, login},
    protocol::{strict_json, valid_id},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub(crate) const PROTOCOL: &str = "mrk-github-actions-retry/1";
pub(crate) const EVENT: &str = "github-actions-retry-status";
pub(crate) const INITIAL_LIMIT: usize = 8192;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const GO_LIMIT: usize = 8192;
pub(crate) const RESPONSE_LIMIT: usize = 192 * 1024;
pub(crate) const RETAINED_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const LAST_REVISION: u32 = u32::MAX - 1;

fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>, BridgeError> {
    serde_json::to_value(v)
        .and_then(|v| serde_json::to_vec(&v))
        .map_err(|_| BridgeError::protocol())
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    Prepare,
    Retry,
    Pending,
    Reconcile,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    InvalidInput,
    TargetChanged,
    SelectionChanged,
    NotRetryable,
    PermissionUnconfirmed,
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
    Unattributed,
    ResourcesUnavailable,
    RuntimeUnavailable,
    Unqualified,
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
    AcceptedUnconfirmed,
    Accepted,
    Unresolved,
    AdvancedUnattributed,
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
pub(crate) struct Selection {
    pub(crate) run_id: String,
    pub(crate) attempt: u32,
    pub(crate) head_sha: String,
    pub(crate) marker: String,
}
impl Selection {
    fn valid(&self) -> bool {
        numeric_id(&self.run_id)
            && (1..=1000).contains(&self.attempt)
            && hex(&self.head_sha, 40)
            && hex(&self.marker, 32)
    }
    fn heap(&self) -> Option<usize> {
        strings(&[&self.run_id, &self.head_sha, &self.marker])
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) scope: Scope,
    #[serde(deserialize_with = "nullable")]
    pub(crate) selection: Option<Selection>,
}
impl Target {
    pub(crate) fn valid(&self) -> bool {
        self.scope.valid() && self.selection.as_ref().is_none_or(Selection::valid)
    }
    pub(crate) fn same_scope(&self, other: &Self) -> bool {
        self.scope.project_binding == other.scope.project_binding
            && self
                .scope
                .repository
                .eq_ignore_ascii_case(&other.scope.repository)
            && self.scope.account_id == other.scope.account_id
            && self.scope.repository_id == other.scope.repository_id
    }
    pub(crate) fn marker(&self) -> Option<&str> {
        self.selection.as_ref().map(|s| s.marker.as_str())
    }
    fn heap(&self) -> Option<usize> {
        self.scope
            .heap()?
            .checked_add(self.selection.as_ref().map_or(Some(0), Selection::heap)?)
    }
}
fn text(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len()<=max && !s.chars().any(|c|c.is_control()||matches!(c,
    '\u{ad}'|'\u{600}'..='\u{605}'|'\u{61c}'|'\u{6dd}'|'\u{70f}'|'\u{890}'..='\u{891}'|'\u{8e2}'|'\u{180e}'|
    '\u{200b}'..='\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2060}'..='\u{2064}'|'\u{2066}'..='\u{206f}'|'\u{feff}'|
    '\u{fff9}'..='\u{fffb}'|'\u{110bd}'|'\u{110cd}'|'\u{13430}'..='\u{1343f}'|'\u{1bca0}'..='\u{1bca3}'|
    '\u{1d173}'..='\u{1d17a}'|'\u{e0001}'|'\u{e0020}'..='\u{e007f}'))
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Run {
    pub(crate) id: String,
    pub(crate) attempt: u32,
    pub(crate) name: String,
    pub(crate) workflow_id: String,
    pub(crate) workflow_path: String,
    pub(crate) status: String,
    #[serde(deserialize_with = "nullable")]
    pub(crate) conclusion: Option<String>,
    pub(crate) head_sha: String,
    #[serde(deserialize_with = "nullable")]
    pub(crate) head_branch: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) head_repository: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) head_repository_id: Option<String>,
    pub(crate) event: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}
impl Run {
    fn valid(&self) -> bool {
        numeric_id(&self.id)
            && numeric_id(&self.workflow_id)
            && (1..=1000).contains(&self.attempt)
            && text(&self.name, 512)
            && text(&self.workflow_path, 512)
            && matches!(
                self.status.as_str(),
                "queued" | "in_progress" | "completed" | "waiting" | "pending" | "requested"
            )
            && self.conclusion.as_deref().is_none_or(|s| {
                matches!(
                    s,
                    "success"
                        | "failure"
                        | "neutral"
                        | "cancelled"
                        | "skipped"
                        | "timed_out"
                        | "action_required"
                        | "stale"
                        | "startup_failure"
                )
            })
            && (self.status == "completed" || self.conclusion.is_none())
            && hex(&self.head_sha, 40)
            && self.head_branch.as_ref().is_none_or(|s| text(s, 200))
            && (self.head_repository.is_none() == self.head_repository_id.is_none())
            && self.head_repository.as_ref().is_none_or(|s| coordinate(s))
            && self
                .head_repository_id
                .as_ref()
                .is_none_or(|s| numeric_id(s))
            && text(&self.event, 64)
            && utc(&self.created_at)
            && utc(&self.updated_at)
    }
    fn same_source(&self, p: &Prepared) -> bool {
        let r = &p.run;
        self.valid()
            && self.id == r.id
            && self.attempt >= r.attempt
            && self.name == r.name
            && self.workflow_id == r.workflow_id
            && self.workflow_path == r.workflow_path
            && self.head_sha == r.head_sha
            && self.head_branch == r.head_branch
            && self.head_repository == r.head_repository
            && self.head_repository_id == r.head_repository_id
            && self.event == r.event
            && self.created_at == r.created_at
    }
    fn heap(&self) -> Option<usize> {
        strings(&[
            &self.id,
            &self.name,
            &self.workflow_id,
            &self.workflow_path,
            &self.status,
            &self.head_sha,
            &self.event,
            &self.created_at,
            &self.updated_at,
        ])?
        .checked_add(self.conclusion.as_ref().map_or(0, String::capacity))?
        .checked_add(self.head_branch.as_ref().map_or(0, String::capacity))?
        .checked_add(self.head_repository.as_ref().map_or(0, String::capacity))?
        .checked_add(self.head_repository_id.as_ref().map_or(0, String::capacity))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepared {
    pub(crate) target: Target,
    pub(crate) account_login: String,
    pub(crate) run: Run,
    retry_permission: String,
    confirmation: String,
}
impl Prepared {
    fn confirmation(&self) -> String {
        format!("Retry failed and dependent jobs for run {} in {}? Observed attempt {}. GitHub may select its latest attempt when it receives this request. This approval is for the same immutable run, workflow {} and source {}, not another run. Dependent jobs may run again, and the workflow may publish or change external services using its existing privileges. Stopping cannot undo an accepted request.",self.run.id,self.target.scope.repository,self.run.attempt,self.run.workflow_id,self.run.head_sha)
    }
    pub(crate) fn valid(&self) -> bool {
        self.target.valid()
            && self.run.valid()
            && login(&self.account_login)
            && self.target.selection.as_ref().is_some_and(|s| {
                s.run_id == self.run.id
                    && s.attempt == self.run.attempt
                    && s.head_sha == self.run.head_sha
            })
            && self.run.status == "completed"
            && matches!(
                self.run.conclusion.as_deref(),
                Some("failure" | "timed_out")
            )
            && self.run.head_repository.as_ref().is_none_or(|r| {
                !r.eq_ignore_ascii_case(&self.target.scope.repository)
                    || self.run.head_repository_id.as_ref()
                        == Some(&self.target.scope.repository_id)
            })
            && self.retry_permission == "not-proven"
            && self.confirmation == self.confirmation()
            && canonical(self).is_ok_and(|b| b.len() <= 4096 - 128)
    }
    pub(crate) fn digest(&self) -> Result<String, BridgeError> {
        canonical(self).map(|b| format!("{:x}", Sha256::digest(b)))
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.target
            .heap()?
            .checked_add(self.run.heap()?)?
            .checked_add(strings(&[
                &self.account_login,
                &self.retry_permission,
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
    pub(crate) home: Option<String>,
    pub(crate) prepared: Option<Prepared>,
}
impl Request {
    pub(crate) fn valid(&self) -> bool {
        self.target.valid()
            && (self.kind == Kind::Pending) == self.target.selection.is_none()
            && (self.kind == Kind::Prepare) == self.home.is_none()
            && self.home.as_ref().is_none_or(|v| {
                v.starts_with('/')
                    && v.len() <= 3968
                    && !v.chars().any(char::is_control)
                    && v.split('/')
                        .skip(1)
                        .all(|p| !p.is_empty() && p != "." && p != "..")
            })
            && matches!(self.kind, Kind::Retry | Kind::Reconcile) == self.prepared.is_some()
            && self
                .prepared
                .as_ref()
                .is_none_or(|p| p.valid() && p.target == self.target)
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.target
            .heap()?
            .checked_add(self.home.as_ref().map_or(0, String::capacity))?
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
        || body.iter().any(|b| matches!(b, b'\n' | b'\r'))
    {
        return Err(BridgeError::protocol());
    }
    let v = strict_json(body)?;
    fn shape(v: &Value, key: &str) -> bool {
        match v {
            Value::Array(rows) => key == "pending" && rows.iter().all(|r| shape(r, "")),
            Value::Object(o) => o.iter().all(|(k, v)| shape(v, k)),
            _ => true,
        }
    }
    if !bounds(&v, limit, nodes, 12) || !shape(&v, "") {
        return Err(BridgeError::protocol());
    }
    Ok(v)
}
pub(crate) fn encode_initial(id: &str, r: &Request) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !r.valid() {
        return Err(BridgeError::invalid());
    }
    let digest = r.prepared.as_ref().map(Prepared::digest).transpose()?;
    let mut b = canonical(
        &serde_json::json!({"protocol":PROTOCOL,"id":id,"action":{"kind":r.kind,"target":r.target,"home":r.home,"preparedSha256":digest}}),
    )?;
    b.push(b'\n');
    if b.len() > INITIAL_LIMIT {
        return Err(BridgeError::invalid());
    }
    Ok(b)
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
// One finite private buffer; every overflow/error zeroizes the SAME original.
// There is no token Value/Debug DTO or temporary unbounded serializer buffer.
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
        w.write_all(b"{\"protocol\":\"mrk-github-actions-retry/1\",\"id\":")?;
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
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Retry {
    pub(crate) effect: Effect,
    pub(crate) reason: Reason,
    pub(crate) claimed: bool,
    pub(crate) acknowledged: bool,
    #[serde(deserialize_with = "nullable")]
    pub(crate) observed: Option<Run>,
    pub(crate) control: GitHubReadControl,
}
impl Retry {
    fn valid(&self, r: &Request) -> bool {
        let Some(p) = r.prepared.as_ref() else {
            return false;
        };
        if !self.control.valid()
            || !self.reason.core()
            || self.acknowledged && !self.claimed
            || self.observed.as_ref().is_some_and(|v| !v.same_source(p))
        {
            return false;
        }
        match self.effect {
            Effect::NotSent => {
                r.kind == Kind::Retry
                    && !self.claimed
                    && !self.acknowledged
                    && self.observed.is_none()
                    && self.reason != Reason::None
            }
            Effect::PotentiallyApplied => {
                r.kind == Kind::Retry
                    && self.claimed
                    && !self.acknowledged
                    && self.observed.is_none()
                    && self.reason != Reason::None
            }
            Effect::AcceptedUnconfirmed => {
                r.kind == Kind::Retry
                    && self.claimed
                    && self.acknowledged
                    && self.observed.is_none()
                    && self.reason != Reason::None
            }
            Effect::Accepted => {
                self.claimed
                    && self.acknowledged
                    && self.observed.is_some()
                    && self.reason == Reason::None
            }
            Effect::Unresolved => {
                r.kind == Kind::Reconcile && self.observed.is_none() && self.reason != Reason::None
            }
            Effect::AdvancedUnattributed => {
                r.kind == Kind::Reconcile
                    && !self.acknowledged
                    && self
                        .observed
                        .as_ref()
                        .is_some_and(|v| v.attempt > p.run.attempt)
                    && self.reason == Reason::Unattributed
            }
            Effect::None => false,
        }
    }
    fn heap(&self) -> Option<usize> {
        self.observed
            .as_ref()
            .map_or(Some(0), Run::heap)?
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
    pub(crate) retry: Option<Retry>,
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
                self.retry.is_none()
                    && self.pending.is_none()
                    && (self.reason == Reason::None) == self.prepared.is_some()
                    && self
                        .prepared
                        .as_ref()
                        .is_none_or(|p| p.valid() && p.target == r.target)
            }
            Kind::Pending => {
                self.retry.is_none()
                    && self.prepared.is_none()
                    && (self.reason == Reason::None) == self.pending.is_some()
                    && self.pending.as_ref().is_none_or(|rows| {
                        let mut ids = std::collections::BTreeSet::new();
                        let mut attempts = std::collections::BTreeSet::new();
                        rows.len() <= 32
                            && rows.iter().all(|p| {
                                p.valid()
                                    && p.prepared.target.same_scope(&r.target)
                                    && ids.insert(p.prepared.target.marker())
                                    && attempts.insert((&p.prepared.run.id, p.prepared.run.attempt))
                            })
                    })
            }
            Kind::Retry | Kind::Reconcile => {
                self.prepared.is_none()
                    && self.pending.is_none()
                    && self
                        .retry
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
    pub(crate) observed: Option<Run>,
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
        for p in &self.pending {
            n = n.checked_add(p.heap()?)?;
        }
        n.checked_add(self.observed.as_ref().map_or(Some(0), Run::heap)?)
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
            .checked_add(self.result.retry.as_ref().map_or(Some(0), Retry::heap)?)?
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
            for p in rows {
                n = n.checked_add(p.heap()?)?;
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
    pub(crate) activity_revision: u32,
    pub(crate) run_id: String,
    pub(crate) attempt: u32,
}
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
    Start(StartArgs),
    Pending(PendingArgs),
    Reconcile(ReconcileArgs),
    Discard(crate::github_setup_protocol::DiscardArgs),
    Cancel(crate::github_setup_protocol::CancelArgs),
}
pub(crate) fn raw_input(_name: &str, bytes: &[u8]) -> Result<Value, BridgeError> {
    if bytes.is_empty() || bytes.len() > 1024 {
        return Err(BridgeError::invalid());
    }
    let v = strict_json(bytes).map_err(|_| BridgeError::invalid())?;
    if !v.is_object() || !bounds(&v, 1024, 48, 4) {
        return Err(BridgeError::invalid());
    }
    Ok(v)
}
pub(crate) fn decode_command(name: &str, v: &Value) -> Result<Command, BridgeError> {
    if !v.is_object() || !bounds(v, 1024, 48, 4) {
        return Err(BridgeError::invalid());
    }
    fn read<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, BridgeError> {
        serde_json::from_value(v.clone()).map_err(|_| BridgeError::invalid())
    }
    let rev = |n: u32| n > 0 && n <= LAST_REVISION;
    Ok(match name {
        "github_actions_retry_status" if v.as_object().is_some_and(|o| o.is_empty()) => {
            Command::Status
        }
        "github_actions_retry_prepare" => {
            let a: PrepareArgs = read(v)?;
            if !valid_id(&a.session_id)
                || !rev(a.expected_revision)
                || !rev(a.expected_connection_revision)
                || !rev(a.activity_revision)
                || !numeric_id(&a.run_id)
                || !(1..=1000).contains(&a.attempt)
            {
                return Err(BridgeError::invalid());
            }
            Command::Prepare(a)
        }
        "github_actions_retry_start" => {
            let a: StartArgs = read(v)?;
            if !valid_id(&a.session_id)
                || !rev(a.expected_revision)
                || !hex(&a.consent_id, 32)
                || !a.confirm
            {
                return Err(BridgeError::invalid());
            }
            Command::Start(a)
        }
        "github_actions_retry_pending" => {
            let a: PendingArgs = read(v)?;
            if !valid_id(&a.session_id)
                || !rev(a.expected_revision)
                || !rev(a.expected_connection_revision)
            {
                return Err(BridgeError::invalid());
            }
            Command::Pending(a)
        }
        "github_actions_retry_reconcile" => {
            let a: ReconcileArgs = read(v)?;
            if !valid_id(&a.session_id) || !rev(a.expected_revision) || !hex(&a.marker, 32) {
                return Err(BridgeError::invalid());
            }
            Command::Reconcile(a)
        }
        "github_actions_retry_discard" => {
            let a: crate::github_setup_protocol::DiscardArgs = read(v)?;
            if !valid_id(&a.session_id) || !rev(a.expected_revision) || !hex(&a.consent_id, 32) {
                return Err(BridgeError::invalid());
            }
            Command::Discard(a)
        }
        "github_actions_retry_cancel" => {
            let a: crate::github_setup_protocol::CancelArgs = read(v)?;
            if !valid_id(&a.operation_id) {
                return Err(BridgeError::invalid());
            }
            Command::Cancel(a)
        }
        _ => return Err(BridgeError::invalid()),
    })
}

#[cfg(test)]
mod actions_retry_data_tests {
    // DATA only: no owner, provider, selected token, home or original IO.
    use super::*;
    fn prepared() -> Prepared {
        let mut p: Prepared = serde_json::from_value(serde_json::json!({
            "target":{"scope":{"projectBinding":"a".repeat(64),"repository":"owner/app","accountId":"11","repositoryId":"22"},
                "selection":{"runId":"31","attempt":2,"headSha":"c".repeat(40),"marker":"b".repeat(32)}},
            "accountLogin":"owner","run":{"id":"31","attempt":2,"name":"Checks","workflowId":"51","workflowPath":".github/workflows/check.yml",
                "status":"completed","conclusion":"failure","headSha":"c".repeat(40),"headBranch":"main","headRepository":"owner/app","headRepositoryId":"22",
                "event":"push","createdAt":"2026-10-20T20:00:00Z","updatedAt":"2026-10-20T20:01:00Z"},
            "retryPermission":"not-proven","confirmation":""})).unwrap();
        p.confirmation = p.confirmation();
        p
    }
    fn request(kind: Kind) -> Request {
        let p = prepared();
        let mut target = p.target.clone();
        if kind == Kind::Pending {
            target.selection = None;
        }
        Request {
            kind,
            target,
            home: (kind != Kind::Prepare).then(|| "/unopened-native-home".into()),
            prepared: matches!(kind, Kind::Retry | Kind::Reconcile).then_some(p),
        }
    }
    fn control() -> Value {
        serde_json::json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false})
    }
    fn reply(kind: Kind) -> Value {
        serde_json::json!({"protocol":PROTOCOL,"id":"inert","result":{"schemaVersion":1,"kind":kind,"reason":"none","prepared":null,"retry":null,"pending":null,"control":control()}})
    }
    fn wire(v: Value) -> Vec<u8> {
        let mut b = serde_json::to_vec(&v).unwrap();
        b.push(b'\n');
        b
    }
    #[test]
    fn actions_retry_raw_never_supplies_account_source_path_or_provider_cas() {
        let v = serde_json::json!({"sessionId":"session-a","expectedRevision":1,"expectedConnectionRevision":2,"activityRevision":3,"runId":"31","attempt":2});
        assert!(decode_command("github_actions_retry_prepare", &v).is_ok());
        for key in [
            "token",
            "root",
            "repository",
            "accountId",
            "headSha",
            "marker",
            "expectedProviderAttempt",
            "debug",
        ] {
            let mut bad = v.clone();
            bad[key] = serde_json::json!("inert");
            assert!(decode_command("github_actions_retry_prepare", &bad).is_err());
        }
        let start = serde_json::json!({"sessionId":"session-a","expectedRevision":3,"consentId":"b".repeat(32),"confirm":true});
        assert!(decode_command("github_actions_retry_start", &start).is_ok());
        let mut bad = start;
        bad["confirm"] = serde_json::json!(false);
        assert!(decode_command("github_actions_retry_start", &bad).is_err());
        for name in ["dispatch", "all", "job", "force", "delete"] {
            assert!(decode_command(
                &format!("github_actions_retry_{name}"),
                &serde_json::json!({})
            )
            .is_err());
        }
        assert!(raw_input(
            "github_actions_retry_status",
            br#"{"duplicate":1,"duplicate":2}"#
        )
        .is_err());
    }
    #[test]
    fn actions_retry_private_frame_and_confirmation_bind_original_run_without_cas_claim() {
        let r = request(Kind::Retry);
        let initial = encode_initial("inert", &r).unwrap();
        let init: Value = serde_json::from_slice(&initial).unwrap();
        assert!(init["action"].get("prepared").is_none());
        assert!(init["action"].get("token").is_none());
        let digest = format!("{:x}", Sha256::digest(&initial));
        let mut private = encode_go("inert", &digest, Some("INERT_NOT_A_TOKEN"), &r).unwrap();
        let decoded: Value = serde_json::from_slice(&private).unwrap();
        assert_eq!(
            decoded["go"]["prepared"]["target"],
            serde_json::to_value(&r.target).unwrap()
        );
        assert_eq!(decoded["go"]["requestSha256"], digest);
        assert!(private.len() <= GO_LIMIT);
        use zeroize::Zeroize;
        private.zeroize();
        let mut p = prepared();
        assert!(p.valid());
        assert!(p.confirmation.contains("latest attempt"));
        assert!(p.confirmation.contains("Dependent jobs may run again"));
        p.retry_permission = "granted".into();
        assert!(!p.valid());
        p = prepared();
        p.run.workflow_id = "52".into();
        assert!(!p.valid());
        assert!(encode_go("inert", &digest, None, &r).is_err());
        assert!(encode_go("inert", &digest, Some(&"\\\"".repeat(2048)), &r).is_err()); // escaped private frame stays finite
        let pending = request(Kind::Pending);
        assert!(encode_go("inert", &digest, None, &pending).is_ok());
        assert!(encode_go("inert", &digest, Some("INERT"), &pending).is_err());
    }
    #[test]
    fn actions_retry_receipt_and_unattributed_new_attempt_are_independent() {
        let r = request(Kind::Retry);
        let mut v = reply(Kind::Retry);
        let mut observed = serde_json::to_value(prepared().run).unwrap();
        observed["attempt"] = serde_json::json!(3);
        v["result"]["retry"] = serde_json::json!({"effect":"accepted","reason":"none","claimed":true,"acknowledged":true,"observed":observed,"control":control()});
        assert!(decode_reply("inert", &wire(v.clone()), &r).is_ok());
        for key in ["claimed", "acknowledged"] {
            let mut bad = v.clone();
            bad["result"]["retry"][key] = serde_json::json!(false);
            assert!(decode_reply("inert", &wire(bad), &r).is_err());
        }
        for (key, value) in [
            ("id", serde_json::json!("32")),
            ("workflowId", serde_json::json!("52")),
            ("event", serde_json::json!("workflow_dispatch")),
            ("attempt", serde_json::json!(1)),
        ] {
            let mut bad = v.clone();
            bad["result"]["retry"]["observed"][key] = value;
            assert!(decode_reply("inert", &wire(bad), &r).is_err());
        }
        v["result"]["kind"] = serde_json::json!("reconcile");
        v["result"]["reason"] = serde_json::json!("unattributed");
        v["result"]["retry"]["reason"] = serde_json::json!("unattributed");
        v["result"]["retry"]["effect"] = serde_json::json!("advanced-unattributed");
        v["result"]["retry"]["acknowledged"] = serde_json::json!(false);
        assert!(decode_reply("inert", &wire(v.clone()), &request(Kind::Reconcile)).is_ok());
        v["result"]["retry"]["acknowledged"] = serde_json::json!(true);
        assert!(decode_reply("inert", &wire(v), &request(Kind::Reconcile)).is_err());
    }
    #[test]
    fn actions_retry_pending_bounds_duplicate_attempts_and_prepare_cannot_restore_permission() {
        let r = request(Kind::Pending);
        let mut v = reply(Kind::Pending);
        let row = serde_json::json!({"prepared":prepared(),"claimed":true,"acknowledged":true});
        v["result"]["pending"] = serde_json::json!([row]);
        assert!(decode_reply("inert", &wire(v.clone()), &r).is_ok());
        let mut duplicate = row.clone();
        duplicate["prepared"]["target"]["selection"]["marker"] = serde_json::json!("e".repeat(32));
        v["result"]["pending"] = serde_json::json!([row, duplicate]);
        assert!(decode_reply("inert", &wire(v), &r).is_err());
        let mut v = reply(Kind::Prepare);
        v["result"]["prepared"] = serde_json::to_value(prepared()).unwrap();
        assert!(decode_reply("inert", &wire(v.clone()), &request(Kind::Prepare)).is_ok());
        v["result"]["retry"] = serde_json::json!({});
        assert!(decode_reply("inert", &wire(v), &request(Kind::Prepare)).is_err());
    }
}
