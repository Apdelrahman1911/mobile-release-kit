//! Closed same-repository draft-PR operation DATA. No token getter, source or permission grant.
use crate::{
    error::BridgeError,
    github_connection_protocol::{bounds, nullable, numeric_id, GitHubReadControl},
    github_preflight_protocol::{branch, hex},
    github_repository_create_protocol::coordinate,
    protocol::{strict_json, valid_id},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[path="github_pull_request_management.rs"]
mod management;

pub(crate) const PROTOCOL: &str = "mrk-github-pull-request/1";
pub(crate) const EVENT: &str = "github-pull-request-status";
pub(crate) const INITIAL_LIMIT: usize = 8192;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const GO_LIMIT: usize = 32 * 1024;
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
    Create,
    Pending,
    Reconcile,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    InvalidInput,
    TargetChanged,
    BranchesChanged,
    PullRequestExists,
    NoChanges,
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
    AcknowledgedUnconfirmed,
    CreatedObserved,
    ClosedConfirmed,
    Unresolved,
    FoundUnattributed,
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
pub(crate) struct Intent {
    pub(crate) base: String,
    pub(crate) head: String,
    pub(crate) marker: String,
    pub(crate) title_sha256: String,
    pub(crate) body_sha256: String,
}
impl Intent {
    fn valid(&self) -> bool {
        branch(&self.base)
            && branch(&self.head)
            && self.base != self.head
            && hex(&self.marker, 32)
            && hex(&self.title_sha256, 64)
            && hex(&self.body_sha256, 64)
    }
    fn heap(&self) -> Option<usize> {
        strings(&[
            &self.base,
            &self.head,
            &self.marker,
            &self.title_sha256,
            &self.body_sha256,
        ])
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) scope: Scope,
    #[serde(deserialize_with = "nullable")]
    pub(crate) intent: Option<Intent>,
}
impl Target {
    pub(crate) fn valid(&self) -> bool {
        self.scope.valid() && self.intent.as_ref().is_none_or(Intent::valid)
    }
    pub(crate) fn same_scope(&self, v: &Self) -> bool {
        self.scope.project_binding == v.scope.project_binding
            && self
                .scope
                .repository
                .eq_ignore_ascii_case(&v.scope.repository)
            && self.scope.account_id == v.scope.account_id
            && self.scope.repository_id == v.scope.repository_id
    }
    fn heap(&self) -> Option<usize> {
        self.scope
            .heap()?
            .checked_add(self.intent.as_ref().map_or(Some(0), Intent::heap)?)
    }
    pub(crate) fn confirmation(&self) -> String {
        let Some(i) = &self.intent else {
            return String::new();
        };
        format!("Create a draft pull request in {} from {} into {} with the text you reviewed? Existing GitHub workflows may run. No code is pushed or merged. This does not authorize a release. Stopping cannot undo a sent request.", self.scope.repository,i.head,i.base)
    }
    pub(crate) fn marker(&self) -> Option<&str> {
        self.intent.as_ref().map(|i| i.marker.as_str())
    }
}
fn text(value: &str, maximum: usize, multiline: bool, empty: bool) -> bool {
    (empty || !value.trim().is_empty()) && value.len()<=maximum && !value.contains("mrk-draft-pr:") && !value.chars().any(|c| {
        if multiline && c=='\n' { return false; }
        c.is_control() || matches!(c,
        '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{890}'..='\u{891}' |
        '\u{8e2}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' |
        '\u{2066}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}' |
        '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}' | '\u{1d173}'..='\u{1d17a}' | '\u{e0001}' | '\u{e0020}'..='\u{e007f}')
    })
}
// Private user input: never Debug or included in the public Status/journal.
// Serialize is used only to stream the retained text through its original GO.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Draft {
    pub(crate) base: String,
    pub(crate) head: String,
    pub(crate) title: String,
    pub(crate) body: String,
}
impl Drop for Draft {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.title.zeroize();
        self.body.zeroize();
    }
}
impl Draft {
    pub(crate) fn valid(&self) -> bool {
        branch(&self.base)
            && branch(&self.head)
            && self.base != self.head
            && text(&self.title, 256, false, false)
            && text(&self.body, 4096, true, true)
    }
    pub(crate) fn intent(&self, marker: String) -> Intent {
        Intent {
            base: self.base.clone(),
            head: self.head.clone(),
            marker,
            title_sha256: format!("{:x}", Sha256::digest(self.title.as_bytes())),
            body_sha256: format!("{:x}", Sha256::digest(self.body.as_bytes())),
        }
    }
    pub(crate) fn matches(&self, t: &Target) -> bool {
        t.intent
            .as_ref()
            .is_some_and(|i| self.valid() && &self.intent(i.marker.clone()) == i)
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        strings(&[&self.base, &self.head, &self.title, &self.body])
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct File {
    path: String,
    change: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Comparison {
    ahead_by: u32,
    behind_by: u32,
    total_commits: u32,
    reported_files: u32,
    coverage: String,
    files: Vec<File>,
}
impl Comparison {
    fn valid(&self) -> bool {
        let mut names = std::collections::BTreeSet::new();
        self.ahead_by > 0
            && [
                self.ahead_by,
                self.behind_by,
                self.total_commits,
                self.reported_files,
            ]
            .iter()
            .all(|n| *n <= i32::MAX as u32)
            && self.coverage == "windowed"
            && self.files.len() <= 4
            && self.reported_files as usize >= self.files.len()
            && self.files.iter().all(|f| {
                text(&f.path, 192, false, false)
                    && names.insert(&f.path)
                    && matches!(
                        f.change.as_str(),
                        "added"
                            | "removed"
                            | "modified"
                            | "renamed"
                            | "copied"
                            | "changed"
                            | "unchanged"
                    )
            })
    }
    fn heap(&self) -> Option<usize> {
        let n = self.coverage.capacity().checked_add(
            self.files
                .capacity()
                .checked_mul(std::mem::size_of::<File>())?,
        )?;
        self.files
            .iter()
            .try_fold(n, |n, f| n.checked_add(strings(&[&f.path, &f.change])?))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepared {
    pub(crate) target: Target,
    pub(super) base_sha: String,
    pub(super) head_sha: String,
    comparison: Comparison,
    draft: bool,
    creation_permission: String,
    confirmation: String,
}
impl Prepared {
    pub(crate) fn valid(&self) -> bool {
        self.target.valid()
            && self.target.intent.is_some()
            && hex(&self.base_sha, 40)
            && hex(&self.head_sha, 40)
            && self.base_sha != self.head_sha
            && self.comparison.valid()
            && self.draft
            && self.creation_permission == "not-proven"
            && self.confirmation == self.target.confirmation()
            && canonical(self).is_ok_and(|v| v.len() <= 4096 - 64)
    }
    pub(crate) fn digest(&self) -> Result<String, BridgeError> {
        canonical(self).map(|v| format!("{:x}", Sha256::digest(v)))
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.target
            .heap()?
            .checked_add(self.comparison.heap()?)?
            .checked_add(strings(&[
                &self.base_sha,
                &self.head_sha,
                &self.creation_permission,
                &self.confirmation,
            ])?)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Acknowledgement {
    pub(crate) id: String,
    pub(crate) number: String,
    pub(crate) url: String,
}
impl Acknowledgement {
    fn valid(&self, p: &Prepared) -> bool {
        numeric_id(&self.id)
            && numeric_id(&self.number)
            && self.url
                == format!(
                    "https://github.com/{}/pull/{}",
                    p.target.scope.repository, self.number
                )
    }
    fn heap(&self) -> Option<usize> {
        strings(&[&self.id, &self.number, &self.url])
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pending {
    pub(crate) prepared: Prepared,
    pub(crate) claimed: bool,
    #[serde(deserialize_with = "nullable")]
    pub(crate) acknowledged: Option<Acknowledgement>,
    #[serde(default, skip_serializing_if="Option::is_none", deserialize_with="management::present")]
    pub(crate) closed: Option<management::Closed>,
}
impl Pending {
    fn valid(&self) -> bool {
        self.prepared.valid()
            && self
                .acknowledged
                .as_ref()
                .is_none_or(|v| self.claimed && v.valid(&self.prepared))
            && self.closed.as_ref().is_none_or(|c| self.claimed && self.acknowledged.as_ref().is_some_and(|a| c.valid(a)))
    }
    fn heap(&self) -> Option<usize> {
        self.prepared.heap()?.checked_add(
            self.acknowledged
                .as_ref()
                .map_or(Some(0), Acknowledgement::heap)?,
        )?.checked_add(self.closed.as_ref().map_or(Some(0), management::Closed::heap)?)
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) kind: Kind,
    pub(crate) target: Target,
    pub(crate) home: Option<String>,
    pub(crate) prepared: Option<Prepared>,
    pub(crate) draft: Option<Draft>,
}
impl Request {
    pub(crate) fn valid(&self) -> bool {
        self.target.valid()
            && (self.kind == Kind::Pending) == self.target.intent.is_none()
            && matches!(self.kind, Kind::Prepare | Kind::Create) == self.draft.is_some()
            && self.draft.as_ref().is_none_or(|d| d.matches(&self.target))
            && (self.kind == Kind::Prepare) == self.home.is_none()
            && self.home.as_ref().is_none_or(|v| {
                v.starts_with('/')
                    && v.len() <= 3968
                    && !v.chars().any(char::is_control)
                    && v.split('/')
                        .skip(1)
                        .all(|p| !p.is_empty() && p != "." && p != "..")
            })
            && matches!(self.kind, Kind::Create | Kind::Reconcile) == self.prepared.is_some()
            && self
                .prepared
                .as_ref()
                .is_none_or(|p| p.valid() && p.target == self.target)
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.target
            .heap()?
            .checked_add(self.home.as_ref().map_or(0, String::capacity))?
            .checked_add(self.prepared.as_ref().map_or(Some(0), Prepared::heap)?)?
            .checked_add(self.draft.as_ref().map_or(Some(0), Draft::heap)?)
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
            Value::Array(rows) => {
                matches!(key, "pending" | "files") && rows.iter().all(|v| shape(v, ""))
            }
            Value::Object(rows) => rows.iter().all(|(k, v)| shape(v, k)),
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
    let hash = r.prepared.as_ref().map(Prepared::digest).transpose()?;
    let mut b = canonical(
        &serde_json::json!({"protocol":PROTOCOL,"id":id,"action":{"kind":r.kind,
        "target":r.target,"home":r.home,"preparedSha256":hash}}),
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
    // Stream the original private token directly into its original finite pipe
    // frame, never a serde Value/public status. Caller zeroizes a refused GO.
    let mut b = Vec::with_capacity(GO_LIMIT);
    b.extend_from_slice(b"{\"protocol\":\"mrk-github-pull-request/1\",\"id\":");
    serde_json::to_writer(&mut b, id).map_err(|_| BridgeError::invalid())?;
    b.extend_from_slice(b",\"go\":{\"requestSha256\":");
    serde_json::to_writer(&mut b, digest).map_err(|_| BridgeError::invalid())?;
    b.extend_from_slice(b",\"prepared\":");
    serde_json::to_writer(&mut b, &r.prepared).map_err(|_| BridgeError::invalid())?;
    b.extend_from_slice(b",\"draft\":");
    serde_json::to_writer(&mut b, &r.draft).map_err(|_| BridgeError::invalid())?;
    b.extend_from_slice(b",\"token\":");
    serde_json::to_writer(&mut b, &token).map_err(|_| BridgeError::invalid())?;
    b.extend_from_slice(b"}}\n");
    if b.len() > GO_LIMIT {
        use zeroize::Zeroize;
        b.zeroize();
        return Err(BridgeError::invalid());
    }
    Ok(b)
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Creation {
    pub(crate) effect: Effect,
    pub(crate) reason: Reason,
    pub(crate) claimed: bool,
    #[serde(deserialize_with = "nullable")]
    pub(crate) acknowledged: Option<Acknowledgement>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) observed: Option<Acknowledgement>,
    pub(crate) control: GitHubReadControl,
}
impl Creation {
    fn valid(&self, r: &Request) -> bool {
        let Some(p) = r.prepared.as_ref() else {
            return false;
        };
        if !self.control.valid()
            || !self.reason.core()
            || self
                .acknowledged
                .as_ref()
                .is_some_and(|v| !self.claimed || !v.valid(p))
            || self.observed.as_ref().is_some_and(|v| !v.valid(p))
        {
            return false;
        }
        match self.effect {
            Effect::NotSent => {
                r.kind == Kind::Create
                    && !self.claimed
                    && self.acknowledged.is_none()
                    && self.observed.is_none()
                    && self.reason != Reason::None
            }
            Effect::PotentiallyApplied => {
                r.kind == Kind::Create
                    && self.acknowledged.is_none()
                    && self.claimed
                    && self.observed.is_none()
                    && self.reason != Reason::None
            }
            Effect::AcknowledgedUnconfirmed => {
                r.kind == Kind::Create
                    && self.claimed
                    && self.acknowledged.is_some()
                    && self.observed.is_none()
                    && self.reason != Reason::None
            }
            Effect::CreatedObserved => {
                self.claimed
                    && self.acknowledged.is_some()
                    && self.acknowledged == self.observed
                    && self.reason == Reason::None
            }
            Effect::ClosedConfirmed => {
                r.kind == Kind::Reconcile && self.claimed && self.acknowledged.is_some()
                    && self.acknowledged == self.observed && self.reason == Reason::None
            }
            Effect::Unresolved => {
                r.kind == Kind::Reconcile && self.observed.is_none() && self.reason != Reason::None
            }
            Effect::FoundUnattributed => {
                r.kind == Kind::Reconcile
                    && self.acknowledged.is_none()
                    && self.observed.is_some()
                    && self.reason == Reason::Unattributed
            }
            Effect::None => false,
        }
    }
    fn heap(&self) -> Option<usize> {
        self.acknowledged
            .as_ref()
            .map_or(Some(0), Acknowledgement::heap)?
            .checked_add(
                self.observed
                    .as_ref()
                    .map_or(Some(0), Acknowledgement::heap)?,
            )?
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
    pub(crate) creation: Option<Creation>,
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
                self.creation.is_none()
                    && self.pending.is_none()
                    && (self.reason == Reason::None) == self.prepared.is_some()
                    && self
                        .prepared
                        .as_ref()
                        .is_none_or(|p| p.valid() && p.target == r.target)
            }
            Kind::Pending => {
                self.creation.is_none()
                    && self.prepared.is_none()
                    && (self.reason == Reason::None) == self.pending.is_some()
                    && self.pending.as_ref().is_none_or(|rows| {
                        let mut ids = std::collections::BTreeSet::new();
                        rows.len() <= 32
                            && rows.iter().all(|p| {
                                p.valid()
                                    && p.prepared.target.same_scope(&r.target)
                                    && ids.insert(p.prepared.target.marker())
                            })
                    })
            }
            Kind::Create | Kind::Reconcile => {
                self.prepared.is_none()
                    && self.pending.is_none()
                    && self
                        .creation
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
    pub(crate) observed: Option<Acknowledgement>,
    pub(crate) acknowledged: Option<Acknowledgement>,
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
        n.checked_add(
            self.observed
                .as_ref()
                .map_or(Some(0), Acknowledgement::heap)?,
        )?
        .checked_add(
            self.acknowledged
                .as_ref()
                .map_or(Some(0), Acknowledgement::heap)?,
        )
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
                    .creation
                    .as_ref()
                    .map_or(Some(0), Creation::heap)?,
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
            for p in rows {
                n = n.checked_add(p.heap()?)?;
            }
        }
        Some(n)
    }
}
fn strings(v: &[&String]) -> Option<usize> {
    v.iter()
        .try_fold(0usize, |n, v| n.checked_add(v.capacity()))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrepareArgs {
    pub(crate) session_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
    pub(crate) draft: Draft,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateArgs {
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
    Create(CreateArgs),
    Pending(PendingArgs),
    Reconcile(ReconcileArgs),
    Discard(crate::github_setup_protocol::DiscardArgs),
    Cancel(crate::github_setup_protocol::CancelArgs),
}
/// The shell accepts only the original RAW UTF-8 bytes. A pre-decoded Tauri
/// Value cannot establish the byte bound or reject duplicate object members.
pub(crate) fn raw_input(name: &str, bytes: &[u8]) -> Result<Value, BridgeError> {
    let maximum = if name == "github_pull_request_prepare" {
        16 * 1024
    } else {
        1024
    };
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(BridgeError::invalid());
    }
    let value = strict_json(bytes).map_err(|_| BridgeError::invalid())?;
    if !value.is_object() || !bounds(&value, maximum, 48, 4) {
        return Err(BridgeError::invalid());
    }
    Ok(value)
}
pub(crate) fn decode_command(name: &str, v: &Value) -> Result<Command, BridgeError> {
    let maximum = if name == "github_pull_request_prepare" {
        16 * 1024
    } else {
        1024
    };
    if !v.is_object() || !bounds(v, maximum, 48, 4) {
        return Err(BridgeError::invalid());
    }
    fn read<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, BridgeError> {
        serde_json::from_value(v.clone()).map_err(|_| BridgeError::invalid())
    }
    let revision = |n: u32| n > 0 && n <= LAST_REVISION;
    Ok(match name {
        "github_pull_request_status" if v.as_object().is_some_and(|o| o.is_empty()) => {
            Command::Status
        }
        "github_pull_request_prepare" => {
            let a: PrepareArgs = read(v)?;
            if !a.draft.valid()
                || !valid_id(&a.session_id)
                || !revision(a.expected_revision)
                || !revision(a.expected_connection_revision)
            {
                return Err(BridgeError::invalid());
            }
            Command::Prepare(a)
        }
        "github_pull_request_create" => {
            let a: CreateArgs = read(v)?;
            if !valid_id(&a.session_id)
                || !revision(a.expected_revision)
                || !hex(&a.consent_id, 32)
                || !a.confirm
            {
                return Err(BridgeError::invalid());
            }
            Command::Create(a)
        }
        "github_pull_request_pending" => {
            let a: PendingArgs = read(v)?;
            if !valid_id(&a.session_id)
                || !revision(a.expected_revision)
                || !revision(a.expected_connection_revision)
            {
                return Err(BridgeError::invalid());
            }
            Command::Pending(a)
        }
        "github_pull_request_reconcile" => {
            let a: ReconcileArgs = read(v)?;
            if !valid_id(&a.session_id) || !revision(a.expected_revision) || !hex(&a.marker, 32) {
                return Err(BridgeError::invalid());
            }
            Command::Reconcile(a)
        }
        "github_pull_request_discard" => {
            let a: crate::github_setup_protocol::DiscardArgs = read(v)?;
            if !valid_id(&a.session_id) || !revision(a.expected_revision) || !hex(&a.consent_id, 32)
            {
                return Err(BridgeError::invalid());
            }
            Command::Discard(a)
        }
        "github_pull_request_cancel" => {
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
mod pull_request_data_tests {
    // DATA grammar and public-output checks only; no owner/ticket/home/HTTP.
    use super::*;
    fn draft() -> Draft {
        Draft {
            base: "main".into(),
            head: "feature/login".into(),
            title: "Review login".into(),
            body: "Approved description\nNo private material".into(),
        }
    }
    fn target() -> Target {
        Target {
            scope: Scope {
                project_binding: "a".repeat(64),
                repository: "owner/app".into(),
                account_id: "11".into(),
                repository_id: "22".into(),
            },
            intent: Some(draft().intent("b".repeat(32))),
        }
    }
    fn prepared() -> Prepared {
        let t = target();
        Prepared {
            confirmation: t.confirmation(),
            target: t,
            base_sha: "c".repeat(40),
            head_sha: "d".repeat(40),
            comparison: Comparison {
                ahead_by: 1,
                behind_by: 0,
                total_commits: 1,
                reported_files: 1,
                coverage: "windowed".into(),
                files: vec![File {
                    path: "app/main.swift".into(),
                    change: "modified".into(),
                }],
            },
            draft: true,
            creation_permission: "not-proven".into(),
        }
    }
    fn request(kind: Kind) -> Request {
        let mut t = target();
        if kind == Kind::Pending {
            t.intent = None;
        }
        Request {
            kind,
            target: t,
            home: (kind != Kind::Prepare).then(|| "/inert-task-home".into()),
            prepared: matches!(kind, Kind::Create | Kind::Reconcile).then(prepared),
            draft: matches!(kind, Kind::Prepare | Kind::Create).then(draft),
        }
    }
    fn wire(v: Value) -> Vec<u8> {
        let mut b = serde_json::to_vec(&v).unwrap();
        b.push(b'\n');
        b
    }
    fn control() -> Value {
        serde_json::json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false})
    }
    fn result(kind: Kind) -> Value {
        serde_json::json!({"protocol":PROTOCOL,"id":"inert","result":{"schemaVersion":1,"kind":kind,"reason":"none","prepared":null,"creation":null,"pending":null,"control":control()}})
    }
    #[test]
    fn pull_request_raw_requires_exact_explicit_draft_and_never_merge_or_token() {
        let v = serde_json::json!({"sessionId":"session-a","expectedRevision":1,"expectedConnectionRevision":9,"draft":draft()});
        assert!(decode_command(
            "github_pull_request_prepare",
            &raw_input(
                "github_pull_request_prepare",
                &serde_json::to_vec(&v).unwrap()
            )
            .unwrap()
        )
        .is_ok());
        for k in [
            "token",
            "root",
            "home",
            "repository",
            "accountId",
            "url",
            "force",
        ] {
            let mut bad = v.clone();
            bad[k] = Value::String("inert".into());
            assert!(decode_command("github_pull_request_prepare", &bad).is_err());
        }
        for name in [
            "github_pull_request_merge",
            "github_pull_request_push",
            "github_pull_request_rerun",
        ] {
            assert!(decode_command(name, &serde_json::json!({})).is_err());
        }
        assert!(raw_input("github_pull_request_prepare", br#"{"draft":{},"draft":{}}"#).is_err());
        assert!(raw_input("github_pull_request_create", &vec![b' '; 1025]).is_err());
        assert!(decode_command("github_pull_request_create",&serde_json::json!({"sessionId":"session-a","expectedRevision":1,"consentId":"e".repeat(32),"confirm":false})).is_err());
        let mut bad = v;
        bad["draft"]["head"] = Value::String("fork:branch".into());
        assert!(decode_command("github_pull_request_prepare", &bad).is_err());
    }
    #[test]
    fn pull_request_private_text_is_bound_but_not_in_initial_or_public_review() {
        let r = request(Kind::Prepare);
        assert!(r.valid());
        let initial = encode_initial("inert", &r).unwrap();
        assert!(!String::from_utf8(initial.clone())
            .unwrap()
            .contains("Approved description"));
        let hash = format!("{:x}", Sha256::digest(&initial));
        let go = encode_go("inert", &hash, Some("inert-not-a-live-token"), &r).unwrap();
        assert!(String::from_utf8(go)
            .unwrap()
            .contains("Approved description"));
        let mut changed = r.clone();
        changed.draft.as_mut().unwrap().title = "Changed".into();
        assert!(!changed.valid());
        let mut v = result(Kind::Prepare);
        v["result"]["prepared"] = serde_json::to_value(prepared()).unwrap();
        assert!(decode_reply("inert", &wire(v.clone()), &r).is_ok());
        assert!(!String::from_utf8(wire(v.clone()))
            .unwrap()
            .contains("Approved description"));
        for (k, value) in [
            ("draft", Value::Bool(false)),
            ("creationPermission", Value::String("granted".into())),
        ] {
            let mut bad = v.clone();
            bad["result"]["prepared"][k] = value;
            assert!(decode_reply("inert", &wire(bad), &r).is_err());
        }
        let mut p = prepared();
        p.comparison.files[0].path = "écran/日本.swift".into();
        assert!(p.valid());
        assert!(std::str::from_utf8(&canonical(&p).unwrap())
            .unwrap()
            .contains("日本"));
    }
    #[test]
    fn pull_request_acknowledgement_and_unattributed_observation_are_distinct() {
        let ack =
            serde_json::json!({"id":"44","number":"3","url":"https://github.com/owner/app/pull/3"});
        let mut v = result(Kind::Create);
        v["result"]["creation"] = serde_json::json!({"effect":"created-observed","reason":"none","claimed":true,"acknowledged":ack,"observed":ack,"control":control()});
        assert!(decode_reply("inert", &wire(v.clone()), &request(Kind::Create)).is_ok());
        v["result"]["creation"]["acknowledged"] = Value::Null;
        assert!(decode_reply("inert", &wire(v.clone()), &request(Kind::Create)).is_err());
        v["result"]["kind"] = Value::String("reconcile".into());
        v["result"]["reason"] = Value::String("unattributed".into());
        v["result"]["creation"]["reason"] = Value::String("unattributed".into());
        v["result"]["creation"]["effect"] = Value::String("found-unattributed".into());
        assert!(decode_reply("inert", &wire(v.clone()), &request(Kind::Reconcile)).is_ok());
        v["result"]["creation"]["observed"]["url"] = Value::String("https://other.invalid".into());
        assert!(decode_reply("inert", &wire(v), &request(Kind::Reconcile)).is_err());
    }
    #[test]
    fn pull_request_pending_is_scope_only_and_never_restores_consent_or_write() {
        let r = request(Kind::Pending);
        assert!(r.valid() && r.target.intent.is_none() && r.draft.is_none());
        let row = serde_json::json!({"prepared":prepared(),"claimed":true,"acknowledged":null});
        let mut v = result(Kind::Pending);
        v["result"]["pending"] = serde_json::json!([row]);
        assert!(decode_reply("inert", &wire(v.clone()), &r).is_ok());
        v["result"]["pending"] = serde_json::json!([row, row]);
        assert!(decode_reply("inert", &wire(v.clone()), &r).is_err());
        v["result"]["pending"] = serde_json::json!([row]);
        v["result"]["pending"][0]["prepared"]["target"]["scope"]["repositoryId"] =
            Value::String("77".into());
        assert!(decode_reply("inert", &wire(v), &r).is_err());
        assert!(encode_go("inert", &"e".repeat(64), Some("inert"), &r).is_err());
        assert!(encode_go("inert", &"e".repeat(64), None, &r).is_ok());
    }
}
