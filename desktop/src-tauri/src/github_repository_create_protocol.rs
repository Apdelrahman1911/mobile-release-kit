//! Closed empty-repository operation DATA. No token getter, source or permission grant.
use crate::{
    error::BridgeError,
    github_connection_protocol::{bounds, nullable, numeric_id, GitHubReadControl},
    github_preflight_protocol::hex,
    protocol::{strict_json, valid_id},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) const PROTOCOL: &str = "mrk-github-repository-create/1";
pub(crate) const EVENT: &str = "github-repository-create-status";
pub(crate) const INITIAL_LIMIT: usize = 8192;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const GO_LIMIT: usize = 8192;
pub(crate) const RESPONSE_LIMIT: usize = 128 * 1024;
pub(crate) const RETAINED_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const LAST_REVISION: u32 = u32::MAX - 1;

fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>, BridgeError> {
    serde_json::to_value(v)
        .and_then(|v| serde_json::to_vec(&v))
        .map_err(|_| BridgeError::protocol())
}
pub(crate) fn login(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 39
        && v.is_ascii()
        && !v.contains("--")
        && v.as_bytes()[0].is_ascii_alphanumeric()
        && v.as_bytes()[v.len() - 1].is_ascii_alphanumeric()
        && v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}
pub(crate) fn coordinate(v: &str) -> bool {
    let Some((owner, name)) = v.split_once('/') else {
        return false;
    };
    login(owner)
        && !name.is_empty()
        && name.len() <= 100
        && !matches!(name, "." | "..")
        && !name.to_ascii_lowercase().ends_with(".git")
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
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
#[serde(rename_all = "lowercase")]
pub(crate) enum OwnerKind {
    User,
    Organization,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Visibility {
    Private,
    Public,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    InvalidInput,
    TargetChanged,
    RepositoryExists,
    MembershipUnconfirmed,
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
    CreatedObserved,
    Unresolved,
    FoundUnattributed,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) project_binding: String,
    pub(crate) repository: String,
    pub(crate) account_id: String,
    pub(crate) account_login: String,
    pub(crate) owner_kind: OwnerKind,
    pub(crate) visibility: Visibility,
    pub(crate) marker: String,
}
impl Target {
    pub(crate) fn valid(&self) -> bool {
        hex(&self.project_binding, 64)
            && coordinate(&self.repository)
            && numeric_id(&self.account_id)
            && login(&self.account_login)
            && hex(&self.marker, 32)
            && (self.owner_kind != OwnerKind::User
                || self
                    .repository
                    .split('/')
                    .next()
                    .is_some_and(|s| s.eq_ignore_ascii_case(&self.account_login)))
    }
    pub(crate) fn same_scope(&self, v: &Self) -> bool {
        self.project_binding == v.project_binding
            && self.repository.eq_ignore_ascii_case(&v.repository)
            && self.account_id == v.account_id
            && self.account_login.eq_ignore_ascii_case(&v.account_login)
    }
    fn heap(&self) -> Option<usize> {
        strings(&[
            &self.project_binding,
            &self.repository,
            &self.account_id,
            &self.account_login,
            &self.marker,
        ])
    }
    pub(crate) fn confirmation(&self) -> String {
        format!("Create {} as a {} GitHub repository? {}No local files, Git commits, remotes, pushes or workflows are added. Organization rules and token permissions still apply. Stopping cannot undo a sent request.",
            self.repository, if self.visibility == Visibility::Private { "PRIVATE" } else { "PUBLIC" },
            if self.visibility == Visibility::Public { "Anyone can see a public repository and files you later upload. " } else { "" })
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepared {
    pub(crate) target: Target,
    pub(crate) owner_id: String,
    pub(crate) membership: String,
    pub(crate) repository_observation: String,
    pub(crate) creation_permission: String,
    pub(crate) auto_init: bool,
    pub(crate) confirmation: String,
}
impl Prepared {
    pub(crate) fn valid(&self) -> bool {
        self.target.valid()
            && numeric_id(&self.owner_id)
            && !self.auto_init
            && self.repository_observation == "not-found-or-inaccessible"
            && self.creation_permission == "not-proven"
            && self.confirmation == self.target.confirmation()
            && match self.target.owner_kind {
                OwnerKind::User => {
                    self.membership == "self" && self.owner_id == self.target.account_id
                }
                OwnerKind::Organization => {
                    matches!(self.membership.as_str(), "active-admin" | "active-member")
                }
            }
            && canonical(self).is_ok_and(|v| v.len() <= 4096)
    }
    pub(crate) fn digest(&self) -> Result<String, BridgeError> {
        canonical(self).map(|v| format!("{:x}", Sha256::digest(v)))
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.target.heap()?.checked_add(strings(&[
            &self.owner_id,
            &self.membership,
            &self.repository_observation,
            &self.creation_permission,
            &self.confirmation,
        ])?)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Repository {
    pub(crate) id: String,
    pub(crate) full_name: String,
    pub(crate) owner_id: String,
    pub(crate) visibility: Visibility,
    pub(crate) url: String,
}
impl Repository {
    fn valid(&self, p: &Prepared) -> bool {
        numeric_id(&self.id)
            && self.owner_id == p.owner_id
            && self.full_name.eq_ignore_ascii_case(&p.target.repository)
            && coordinate(&self.full_name)
            && self.visibility == p.target.visibility
            && self.url == format!("https://github.com/{}", self.full_name)
    }
    fn heap(&self) -> Option<usize> {
        strings(&[&self.id, &self.full_name, &self.owner_id, &self.url])
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pending {
    pub(crate) prepared: Prepared,
    pub(crate) claimed: bool,
    #[serde(deserialize_with = "nullable")]
    pub(crate) acknowledged: Option<Repository>,
}
impl Pending {
    fn valid(&self) -> bool {
        self.prepared.valid()
            && self
                .acknowledged
                .as_ref()
                .is_none_or(|v| self.claimed && v.valid(&self.prepared))
    }
    fn heap(&self) -> Option<usize> {
        self.prepared.heap()?.checked_add(
            self.acknowledged
                .as_ref()
                .map_or(Some(0), Repository::heap)?,
        )
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
            Value::Array(rows) => key == "pending" && rows.iter().all(|v| shape(v, "")),
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
    b.extend_from_slice(b"{\"protocol\":\"mrk-github-repository-create/1\",\"id\":");
    serde_json::to_writer(&mut b, id).map_err(|_| BridgeError::invalid())?;
    b.extend_from_slice(b",\"go\":{\"requestSha256\":");
    serde_json::to_writer(&mut b, digest).map_err(|_| BridgeError::invalid())?;
    b.extend_from_slice(b",\"prepared\":");
    serde_json::to_writer(&mut b, &r.prepared).map_err(|_| BridgeError::invalid())?;
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
    pub(crate) acknowledged: Option<Repository>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) observed: Option<Repository>,
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
                    && self.claimed
                    && self.observed.is_none()
                    && self.reason != Reason::None
            }
            Effect::CreatedObserved => {
                self.claimed
                    && self.acknowledged.is_some()
                    && self.acknowledged == self.observed
                    && self.reason == Reason::None
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
            .map_or(Some(0), Repository::heap)?
            .checked_add(self.observed.as_ref().map_or(Some(0), Repository::heap)?)?
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
                                    && ids.insert(&p.prepared.target.marker)
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
    pub(crate) observed: Option<Repository>,
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
        n.checked_add(self.observed.as_ref().map_or(Some(0), Repository::heap)?)
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
    pub(crate) owner_kind: OwnerKind,
    pub(crate) visibility: Visibility,
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
pub(crate) fn raw_input(bytes: &[u8]) -> Result<Value, BridgeError> {
    if bytes.is_empty() || bytes.len() > 1024 {
        return Err(BridgeError::invalid());
    }
    let value = strict_json(bytes).map_err(|_| BridgeError::invalid())?;
    if !value.is_object() || !bounds(&value, 1024, 32, 3) {
        return Err(BridgeError::invalid());
    }
    Ok(value)
}
pub(crate) fn decode_command(name: &str, v: &Value) -> Result<Command, BridgeError> {
    if !v.is_object() || !bounds(v, 1024, 32, 3) {
        return Err(BridgeError::invalid());
    }
    fn read<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, BridgeError> {
        serde_json::from_value(v.clone()).map_err(|_| BridgeError::invalid())
    }
    let revision = |n: u32| n > 0 && n <= LAST_REVISION;
    Ok(match name {
        "github_repository_create_status" if v.as_object().is_some_and(|o| o.is_empty()) => {
            Command::Status
        }
        "github_repository_create_prepare" => {
            let a: PrepareArgs = read(v)?;
            if !valid_id(&a.session_id)
                || !revision(a.expected_revision)
                || !revision(a.expected_connection_revision)
            {
                return Err(BridgeError::invalid());
            }
            Command::Prepare(a)
        }
        "github_repository_create_create" => {
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
        "github_repository_create_pending" => {
            let a: PendingArgs = read(v)?;
            if !valid_id(&a.session_id)
                || !revision(a.expected_revision)
                || !revision(a.expected_connection_revision)
            {
                return Err(BridgeError::invalid());
            }
            Command::Pending(a)
        }
        "github_repository_create_reconcile" => {
            let a: ReconcileArgs = read(v)?;
            if !valid_id(&a.session_id) || !revision(a.expected_revision) || !hex(&a.marker, 32) {
                return Err(BridgeError::invalid());
            }
            Command::Reconcile(a)
        }
        "github_repository_create_discard" => {
            let a: crate::github_setup_protocol::DiscardArgs = read(v)?;
            if !valid_id(&a.session_id) || !revision(a.expected_revision) || !hex(&a.consent_id, 32)
            {
                return Err(BridgeError::invalid());
            }
            Command::Discard(a)
        }
        "github_repository_create_cancel" => {
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
mod tests {
    // Pure bounded grammar/codec DATA only. No Supervisor, runtime, source,
    // native session, home access, HTTP or credential owner is manufactured.
    use super::*;
    fn target() -> Target {
        Target {
            project_binding: "a".repeat(64),
            repository: "owner/new-app".into(),
            account_id: "11".into(),
            account_login: "owner".into(),
            owner_kind: OwnerKind::User,
            visibility: Visibility::Private,
            marker: "b".repeat(32),
        }
    }
    fn prepared() -> Prepared {
        let t = target();
        Prepared {
            confirmation: t.confirmation(),
            target: t,
            owner_id: "11".into(),
            membership: "self".into(),
            repository_observation: "not-found-or-inaccessible".into(),
            creation_permission: "not-proven".into(),
            auto_init: false,
        }
    }
    fn request(kind: Kind) -> Request {
        Request {
            kind,
            target: target(),
            home: (kind != Kind::Prepare).then(|| "/inert-task-home".into()),
            prepared: matches!(kind, Kind::Create | Kind::Reconcile).then(prepared),
        }
    }
    fn control() -> Value {
        serde_json::json!({"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false})
    }
    fn wire(value: &Value) -> Vec<u8> {
        let mut b = serde_json::to_vec(value).unwrap();
        b.push(b'\n');
        b
    }
    fn result(kind: Kind) -> Value {
        serde_json::json!({"protocol":PROTOCOL,"id":"fixture","result":{"schemaVersion":1,"kind":kind,"reason":"none",
            "prepared":null,"creation":null,"pending":null,"control":control()}})
    }
    #[test]
    fn repository_create_raw_commands_require_exact_small_original_inputs() {
        let p = serde_json::json!({"sessionId":"session-a","expectedRevision":1,"expectedConnectionRevision":12,"ownerKind":"user","visibility":"private"});
        assert!(decode_command(
            "github_repository_create_prepare",
            &raw_input(&serde_json::to_vec(&p).unwrap()).unwrap()
        )
        .is_ok());
        for key in [
            "token",
            "home",
            "root",
            "accountId",
            "url",
            "body",
            "force",
            "repository",
        ] {
            let mut v = p.clone();
            v[key] = Value::String("inert".into());
            assert!(decode_command("github_repository_create_prepare", &v).is_err());
        }
        assert!(raw_input(br#"{"confirm":true,"confirm":false}"#).is_err());
        assert!(raw_input(&vec![b' '; 1025]).is_err());
        assert!(raw_input(br#"[]"#).is_err());
        assert!(raw_input(&[0xff]).is_err());
        let a = serde_json::json!({"sessionId":"session-a","expectedRevision":1,"consentId":"c".repeat(32),"confirm":false});
        assert!(decode_command("github_repository_create_create", &a).is_err());
        assert!(decode_command("github_repository_create_delete", &serde_json::json!({})).is_err());
    }
    #[test]
    fn repository_create_prepare_is_nonpermission_and_exact_original_bound() {
        let r = request(Kind::Prepare);
        assert!(r.valid());
        let mut v = result(Kind::Prepare);
        v["result"]["prepared"] = serde_json::to_value(prepared()).unwrap();
        assert!(decode_reply("fixture", &wire(&v), &r).is_ok());
        for (key, value) in [
            ("autoInit", Value::Bool(true)),
            ("creationPermission", Value::String("granted".into())),
            ("repositoryObservation", Value::String("absent".into())),
            ("ownerId", Value::String("22".into())),
        ] {
            let mut changed = v.clone();
            changed["result"]["prepared"][key] = value;
            assert!(decode_reply("fixture", &wire(&changed), &r).is_err());
        }
        let mut changed = r;
        changed.target.marker = "c".repeat(32);
        assert!(decode_reply("fixture", &wire(&v), &changed).is_err());
        let mut public = prepared();
        public.target.visibility = Visibility::Public;
        assert!(!public.valid());
        public.confirmation = public.target.confirmation();
        assert!(public.valid());
        assert!(public.confirmation.contains("Anyone can see"));
    }
    #[test]
    fn repository_create_name_only_readback_is_never_original_creation_success() {
        let repo = serde_json::json!({"id":"33","fullName":"owner/new-app","ownerId":"11","visibility":"private","url":"https://github.com/owner/new-app"});
        let r = request(Kind::Create);
        let mut v = result(Kind::Create);
        v["result"]["creation"] = serde_json::json!({"effect":"created-observed","reason":"none","claimed":true,
            "acknowledged":repo,"observed":repo,"control":control()});
        assert!(decode_reply("fixture", &wire(&v), &r).is_ok());
        let mut no_ack = v.clone();
        no_ack["result"]["creation"]["acknowledged"] = Value::Null;
        assert!(decode_reply("fixture", &wire(&no_ack), &r).is_err());
        let mut wrong_id = v.clone();
        wrong_id["result"]["creation"]["observed"]["id"] = Value::String("44".into());
        assert!(decode_reply("fixture", &wire(&wrong_id), &r).is_err());
        let mut unattributed = no_ack;
        unattributed["result"]["kind"] = Value::String("reconcile".into());
        unattributed["result"]["reason"] = Value::String("unattributed".into());
        unattributed["result"]["creation"]["reason"] = Value::String("unattributed".into());
        unattributed["result"]["creation"]["effect"] = Value::String("found-unattributed".into());
        assert!(decode_reply("fixture", &wire(&unattributed), &request(Kind::Reconcile)).is_ok());
        assert!(decode_reply("fixture", &wire(&unattributed), &r).is_err());
    }
    #[test]
    fn repository_create_pending_and_ready_cannot_change_original_scope_or_fabricate_go() {
        let mut v = result(Kind::Pending);
        let row = serde_json::json!({"prepared":prepared(),"claimed":false,"acknowledged":null});
        v["result"]["pending"] = serde_json::json!([row]);
        assert!(decode_reply("fixture", &wire(&v), &request(Kind::Pending)).is_ok());
        v["result"]["pending"] = serde_json::json!([row, row]);
        assert!(decode_reply("fixture", &wire(&v), &request(Kind::Pending)).is_err());
        let initial = encode_initial("fixture", &request(Kind::Prepare)).unwrap();
        let digest = format!("{:x}", Sha256::digest(initial));
        let ready = wire(
            &serde_json::json!({"protocol":PROTOCOL,"id":"fixture","ready":{"requestSha256":digest}}),
        );
        assert!(decode_ready(&ready, "fixture", &digest).is_ok());
        assert!(decode_ready(&ready, "other", &digest).is_err());
        assert!(encode_go("fixture", &digest, None, &request(Kind::Prepare)).is_err());
        assert!(encode_go("fixture", &digest, None, &request(Kind::Pending)).is_ok());
        for coordinate in [
            "https://github.com/owner/app",
            "owner/..",
            "owner/app.git",
            "owner/a/b",
            "owner/app\n",
            "owner/app?x",
        ] {
            assert!(!super::coordinate(coordinate));
        }
    }
}
