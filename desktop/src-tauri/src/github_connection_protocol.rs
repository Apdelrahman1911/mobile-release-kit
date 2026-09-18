//! Closed G1 public status and private read-only wire. This pure module never
//! acquires credentials, starts transport, owns timers or enables a native gate.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use crate::{error::BridgeError, github_workflow_edit_protocol::WorkflowId,
    protocol::{strict_json, valid_id}};

pub const EVENT: &str = "github-connection-status";
pub const PRIVATE_PROTOCOL: &str = "mrk-github-readonly/1";
pub const STATUS_LIMIT: usize = 64 * 1024;
pub const REQUEST_LIMIT: usize = 8 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024;
pub(crate) const COOLDOWN_MAX_SECONDS: u32 = 604800;
const IDS: [WorkflowId; 4] = [WorkflowId::Preflight, WorkflowId::Candidate, WorkflowId::ExternalTesting, WorkflowId::ProductionSubmit];

// deserialize_with makes nullable fields REQUIRED, unlike a bare serde Option.
fn nullable<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where D: Deserializer<'de>, T: Deserialize<'de> { Option::<T>::deserialize(decoder) }

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Reason { None, Unqualified, RuntimeUnavailable, PublisherUnconfigured, NotConnected, InvalidInput,
    Busy, Unauthorized, Forbidden, NotFoundOrInaccessible, TargetChanged, RateLimited, NetworkUnavailable,
    TlsFailed, ResponseInvalid, ResponseLimit, Expired, Stale, Cancelled, CleanupUnknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FactState { NotObserved, Observed, Stale, Unavailable }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields, bound(deserialize = "T: Deserialize<'de>"))]
pub struct Fact<T> {
    pub state: FactState,
    #[serde(deserialize_with = "nullable")] pub value: Option<T>,
    #[serde(deserialize_with = "nullable")] pub observed_at: Option<String>,
    pub reason: Reason,
}
impl<T> Fact<T> {
    fn valid(&self, check: impl Fn(&T) -> bool) -> bool {
        match self.state {
            FactState::NotObserved | FactState::Unavailable => self.value.is_none() && self.observed_at.is_none()
                && self.reason != Reason::None && (self.state != FactState::NotObserved || self.reason == Reason::NotConnected),
            FactState::Observed | FactState::Stale => self.value.as_ref().is_some_and(check)
                && self.observed_at.as_ref().is_some_and(|s| utc(s))
                && (self.reason == Reason::None) == (self.state == FactState::Observed),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Account { pub id: String, pub login: String }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Permission { ReportedAllowed, ReportedDenied, Unknown }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Permissions { pub pull: Permission, pub push: Permission, pub admin: Permission }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Visibility { Public, Private, Internal }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Repository {
    pub id: String, pub full_name: String, pub default_branch: String, pub visibility: Visibility,
    pub archived: bool, pub permissions: Permissions,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Coverage { Complete, Limited }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Presence { Listed, NotListed, Unknown }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WorkflowState { Active, Disabled, Unknown }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Workflow {
    pub id: WorkflowId,
    #[serde(deserialize_with = "nullable")] pub remote_id: Option<String>,
    pub presence: Presence, pub state: WorkflowState,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Automation { pub coverage: Coverage, pub workflows: Vec<Workflow> }
impl Automation {
    fn valid(&self) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        self.workflows.len() == 4 && self.workflows.iter().zip(IDS).all(|(row, id)| {
            row.id == id && row.presence != (if self.coverage == Coverage::Complete { Presence::Unknown } else { Presence::NotListed })
                && match row.presence {
                    Presence::Listed => row.remote_id.as_ref().is_some_and(|v| numeric_id(v) && seen.insert(v)),
                    _ => row.remote_id.is_none() && row.state == WorkflowState::Unknown,
                }
        })
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceLogin { PublisherUnconfigured, NotQualified }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capability {
    pub read_only_session_available: bool, pub reason: Reason, pub device_login: DeviceLogin, pub storage: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SessionState { Checking, Connected, Expired, Disconnecting, Failed, CleanupUnknown }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Session {
    pub id: String, pub project_id: String, pub target_repository: String, pub state: SessionState,
    #[serde(deserialize_with = "nullable")] pub expires_at: Option<String>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OperationKind { Connect, Refresh, Disconnect }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Phase { Running, Settled, CleanupUnknown }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation { pub id: String, pub kind: OperationKind, pub phase: Phase, pub reason: Reason }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnobservedFacts {
    pub remote_mutation_available: bool, pub dispatch_available: bool, pub repository_actions_settings_observation: String,
    pub environment_observation: String, pub secret_observation: String, pub variable_observation: String,
    pub protection_observation: String, pub runner_observation: String, pub template_compatibility: String, pub release_readiness: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub schema_version: u32, pub revision: u32, pub capability: Capability,
    #[serde(deserialize_with = "nullable")] pub session: Option<Session>,
    #[serde(deserialize_with = "nullable")] pub operation: Option<Operation>,
    pub account: Fact<Account>, pub repository: Fact<Repository>, pub automation: Fact<Automation>, pub facts: UnobservedFacts,
}

fn numeric_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20 && !value.starts_with('0')
        && value.bytes().all(|b| b.is_ascii_digit()) && value.parse::<u64>().is_ok()
}
fn coordinate(value: &str) -> bool {
    let Some((owner, repository)) = value.split_once('/') else { return false; };
    let part = |s: &str, limit: usize, punctuation: &[u8]| !s.is_empty() && s.len() <= limit
        && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && s.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || punctuation.contains(&b));
    part(owner, 39, b"-") && part(repository, 100, b"._-")
}
fn plain(value: &str, maximum: usize) -> bool {
    // Cc/Cf are excluded, including directional/zero-width controls. Unicode
    // Rust strings cannot contain the Cs lone surrogates rejected by TS/Python.
    !value.trim().is_empty() && value.len() <= maximum && !value.chars().any(|c| c.is_control() || matches!(c,
        '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{890}'..='\u{891}' |
        '\u{8e2}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' |
        '\u{2066}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}' |
        '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}' | '\u{1d173}'..='\u{1d17a}' | '\u{e0001}' | '\u{e0020}'..='\u{e007f}'))
}
fn utc(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 20 || !value.is_ascii() || b[4] != b'-' || b[7] != b'-' || b[10] != b'T'
        || b[13] != b':' || b[16] != b':' || b[19] != b'Z'
        || b.iter().enumerate().any(|(i, c)| ![4, 7, 10, 13, 16, 19].contains(&i) && !c.is_ascii_digit()) { return false; }
    let n = |start, end| value[start..end].parse::<u32>().unwrap_or(0);
    let (year, month, day) = (n(0, 4), n(5, 7), n(8, 10));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum = match month { 2 => if leap { 29 } else { 28 }, 4 | 6 | 9 | 11 => 30, 1 | 3 | 5 | 7 | 8 | 10 | 12 => 31, _ => 0 };
    year > 0 && day > 0 && day <= maximum && n(11, 13) < 24 && n(14, 16) < 60 && n(17, 19) < 60
}
fn bounds(value: &Value, bytes: usize, nodes_limit: usize, depth_limit: usize) -> bool {
    let mut stack = vec![(value, 0usize)]; let mut nodes = 0usize;
    while let Some((row, depth)) = stack.pop() {
        nodes += 1;
        if nodes > nodes_limit || depth > depth_limit { return false; }
        match row {
            Value::Object(items) => {
                nodes += items.len();
                if depth >= depth_limit || nodes + stack.len() + items.len() > nodes_limit { return false; }
                stack.extend(items.values().map(|v| (v, depth + 1)));
            },
            Value::Array(items) => {
                if depth >= depth_limit || nodes + stack.len() + items.len() > nodes_limit { return false; }
                stack.extend(items.iter().map(|v| (v, depth + 1)));
            },
            _ => {},
        }
    }
    serde_json::to_vec(value).is_ok_and(|v| v.len() <= bytes)
}
impl Status {
    fn valid(&self) -> bool {
        let cap = &self.capability; let f = &self.facts;
        if self.schema_version != 1 || self.revision == 0 || cap.storage != "session-only"
            || cap.read_only_session_available != (cap.reason == Reason::None)
            || (cap.reason == Reason::CleanupUnknown) != self.session.as_ref().is_some_and(|s| s.state == SessionState::CleanupUnknown)
            || [self.account.reason, self.repository.reason, self.automation.reason].contains(&Reason::CleanupUnknown)
                && !self.session.as_ref().is_some_and(|s| s.state == SessionState::CleanupUnknown)
            || f.remote_mutation_available || f.dispatch_available || f.template_compatibility != "unknown" || f.release_readiness != "unknown"
            || [&f.repository_actions_settings_observation, &f.environment_observation, &f.secret_observation,
                &f.variable_observation, &f.protection_observation, &f.runner_observation].iter().any(|v| v.as_str() != "not-run")
            || !self.account.valid(|v| numeric_id(&v.id) && plain(&v.login, 96))
            || !self.repository.valid(|v| numeric_id(&v.id) && coordinate(&v.full_name) && plain(&v.default_branch, 1024))
            || !self.automation.valid(Automation::valid)
            || self.repository.value.is_some() && self.account.value.is_none()
            || self.automation.value.is_some() && self.repository.value.is_none()
            || self.repository.state == FactState::Observed && self.account.state != FactState::Observed
            || self.automation.state == FactState::Observed && self.repository.state != FactState::Observed { return false; }
        let states = [self.account.state, self.repository.state, self.automation.state];
        let Some(session) = &self.session else { return self.operation.is_none() && states.iter().all(|s| *s == FactState::NotObserved); };
        if !valid_id(&session.id) || !valid_id(&session.project_id) || !coordinate(&session.target_repository)
            || session.expires_at.as_ref().is_some_and(|v| !utc(v))
            || self.repository.value.as_ref().is_some_and(|v| !v.full_name.eq_ignore_ascii_case(&session.target_repository)) { return false; }
        if let Some(op) = &self.operation {
            if !valid_id(&op.id) || (op.phase == Phase::CleanupUnknown) != (op.reason == Reason::CleanupUnknown)
                || op.phase == Phase::Running && op.reason != Reason::None
                || op.phase == Phase::CleanupUnknown && session.state != SessionState::CleanupUnknown { return false; }
        }
        let op = self.operation.as_ref();
        match session.state {
            SessionState::Checking => op.is_some_and(|v| v.kind != OperationKind::Disconnect && v.phase == Phase::Running)
                && !states.contains(&FactState::Observed),
            SessionState::Connected => session.expires_at.is_some() && self.account.state == FactState::Observed
                && op.is_none_or(|v| v.phase == Phase::Settled && v.kind != OperationKind::Disconnect),
            SessionState::Disconnecting => op.is_some_and(|v| v.kind == OperationKind::Disconnect && v.phase == Phase::Running)
                && !states.contains(&FactState::Observed),
            SessionState::CleanupUnknown => op.is_some_and(|v| v.phase == Phase::CleanupUnknown)
                && !cap.read_only_session_available && cap.reason == Reason::CleanupUnknown && !states.contains(&FactState::Observed),
            SessionState::Expired | SessionState::Failed => op.is_none_or(|v| v.phase == Phase::Settled)
                && (session.state != SessionState::Expired || session.expires_at.is_some()) && !states.contains(&FactState::Observed),
        }
    }
}
pub fn decode_status(bytes: &[u8]) -> Result<Status, BridgeError> {
    if bytes.len() > STATUS_LIMIT { return Err(BridgeError::protocol()); }
    let value = strict_json(bytes)?;
    if !bounds(&value, STATUS_LIMIT, 2000, 12) { return Err(BridgeError::protocol()); }
    let status: Status = serde_json::from_value(value).map_err(|_| BridgeError::protocol())?;
    if !status.valid() { return Err(BridgeError::protocol()); }
    Ok(status)
}

// Safe private outcome data only: not a renderer status or generic API result.
// In particular these types do not derive Serialize or contain a request/token.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GitHubReadFacts {
    pub(crate) schema_version: u32,
    pub(crate) account: Fact<Account>,
    pub(crate) repository: Fact<Repository>,
    pub(crate) automation: Fact<Automation>,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GitHubReadControl {
    pub(crate) reason: Reason,
    #[serde(deserialize_with = "nullable")]
    pub(crate) credential_expires_at: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) cooldown_seconds: Option<u32>,
    pub(crate) cooldown_blocked: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GitHubReadOutcome {
    pub(crate) facts: GitHubReadFacts,
    pub(crate) control: GitHubReadControl,
}
fn private_reason(reason: Reason) -> bool {
    matches!(reason, Reason::None | Reason::Unauthorized | Reason::Forbidden
        | Reason::NotFoundOrInaccessible | Reason::TargetChanged | Reason::RateLimited
        | Reason::NetworkUnavailable | Reason::TlsFailed | Reason::ResponseInvalid
        | Reason::ResponseLimit | Reason::Expired | Reason::Cancelled)
}
impl GitHubReadFacts {
    fn valid(&self) -> bool {
        let fresh = |state, reason| matches!(state, FactState::Observed | FactState::Unavailable)
            && private_reason(reason);
        self.schema_version == 1
            && fresh(self.account.state, self.account.reason)
            && fresh(self.repository.state, self.repository.reason)
            && fresh(self.automation.state, self.automation.reason)
            && self.account.valid(|v| numeric_id(&v.id) && plain(&v.login, 96))
            && self.repository.valid(|v| numeric_id(&v.id) && coordinate(&v.full_name) && plain(&v.default_branch, 1024))
            && self.automation.valid(Automation::valid)
            && (self.repository.value.is_none() || self.account.value.is_some())
            && (self.automation.value.is_none() || self.repository.value.is_some())
            && (self.repository.state != FactState::Observed || self.account.state == FactState::Observed)
            && (self.automation.state != FactState::Observed || self.repository.state == FactState::Observed)
    }
    fn all_observed(&self) -> bool {
        self.account.state == FactState::Observed && self.repository.state == FactState::Observed
            && self.automation.state == FactState::Observed
    }
    fn coherent_with(&self, control: &GitHubReadControl) -> bool {
        if control.reason == Reason::None && !self.all_observed() { return false; }
        // A final failure/control may dominate earlier observations or cancelled
        // dependents, so facts need not all repeat the overall disposition. But
        // no fact veto may be weakened into a retryable credential/cooldown grant.
        // ResponseInvalid is the stronger retiring refusal, not field salvage.
        [self.account.reason, self.repository.reason, self.automation.reason].into_iter().all(|reason| match reason {
            Reason::Unauthorized | Reason::TargetChanged | Reason::Expired =>
                control.reason == reason || control.reason == Reason::ResponseInvalid,
            Reason::ResponseInvalid => control.reason == Reason::ResponseInvalid,
            Reason::RateLimited => matches!(control.reason, Reason::RateLimited | Reason::ResponseInvalid)
                && (control.cooldown_seconds.is_some() || control.cooldown_blocked),
            Reason::None | Reason::Forbidden | Reason::NotFoundOrInaccessible
                | Reason::NetworkUnavailable | Reason::TlsFailed | Reason::ResponseLimit | Reason::Cancelled => true,
            _ => false,
        })
    }
}
impl GitHubReadControl {
    fn valid(&self) -> bool {
        if !private_reason(self.reason)
            || self.credential_expires_at.as_ref().is_some_and(|v| !utc(v))
            || self.cooldown_seconds.is_some_and(|v| !(1..=COOLDOWN_MAX_SECONDS).contains(&v))
            || self.cooldown_blocked && self.cooldown_seconds.is_some() { return false; }
        match self.reason {
            Reason::RateLimited => self.cooldown_seconds.is_some() || self.cooldown_blocked,
            // Malformed expiry retires the credential but must not erase an
            // independently established cooldown. Malformation alone is not a
            // source of blocked authority; the trusted helper enforces that.
            Reason::ResponseInvalid => true,
            _ => self.cooldown_seconds.is_none() && !self.cooldown_blocked,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateResponse {
    protocol: String, id: String, facts: GitHubReadFacts, control: GitHubReadControl,
}
pub(crate) fn decode_private_response(id: &str, bytes: &[u8]) -> Result<GitHubReadOutcome, BridgeError> {
    if !valid_id(id) || bytes.len() > RESPONSE_LIMIT || !bytes.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &bytes[..bytes.len() - 1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}')
        || body.iter().any(|b| matches!(*b, b'\n' | b'\r')) { return Err(BridgeError::protocol()); }
    let value = strict_json(body)?;
    if !bounds(&value, RESPONSE_LIMIT, 2000, 12) { return Err(BridgeError::protocol()); }
    let response: PrivateResponse = serde_json::from_value(value).map_err(|_| BridgeError::protocol())?;
    if response.protocol != PRIVATE_PROTOCOL || response.id != id || !response.facts.valid() || !response.control.valid()
        || !response.facts.coherent_with(&response.control) { return Err(BridgeError::protocol()); }
    // A canonical private timestamp is reserved data syntax, not evidence of a
    // GitHub header grammar. The current live helper emits null and refuses any
    // present unsupported expiry header instead of guessing its date format.
    Ok(GitHubReadOutcome { facts: response.facts, control: response.control })
}

// PRIVATE inbound-only types: no Debug, Clone or Serialize. In particular no
// renderer state/event/error DTO can be obtained by serializing these requests.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConnectTokenArgs { pub(crate) project_id: String, pub(crate) repository: String, pub(crate) token: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RefreshArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32 }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DisconnectArgs { pub(crate) session_id: String }
pub(crate) enum Command { Status, ConnectToken(ConnectTokenArgs), Refresh(RefreshArgs), Disconnect(DisconnectArgs) }
fn private_token(value: &str) -> bool { !value.is_empty() && value.len() <= 4096 && value.bytes().all(|b| (0x21..=0x7e).contains(&b)) }
fn quoted_size(value: &str, limit: usize) -> Option<usize> {
    let mut size = 2usize;
    for character in value.chars() {
        size = size.checked_add(match character {
            '"' | '\\' | '\u{8}' | '\u{9}' | '\u{a}' | '\u{c}' | '\u{d}' => 2,
            '\u{0}'..='\u{1f}' => 6,
            _ => character.len_utf8(),
        })?;
        if size > limit { return None; }
    }
    (size <= limit).then_some(size)
}
pub(crate) fn decode_command_value(name: &str, value: &Value) -> Result<Command, BridgeError> {
    // The actual IPC already parsed JSON: original lexical duplicates cannot be
    // recovered here. Validate a tiny flat borrowed object before cloning any
    // credential. No serializer, unbounded traversal, token Debug or request
    // Value copy is used. <=3 scalar fields implies <=7 nodes/depth1.
    if !matches!(name, "github_connection_status" | "github_connection_connect_token"
        | "github_connection_refresh" | "github_connection_disconnect") { return Err(BridgeError::invalid()); }
    let object = value.as_object().ok_or_else(BridgeError::invalid)?;
    if object.len() > 3 { return Err(BridgeError::invalid()); }
    let mut size = 2 + object.len().saturating_sub(1);
    for (key, value) in object {
        size = size.checked_add(quoted_size(key, REQUEST_LIMIT).ok_or_else(BridgeError::invalid)? + 1)
            .ok_or_else(BridgeError::invalid)?;
        let scalar = match value {
            Value::String(v) => quoted_size(v, REQUEST_LIMIT).ok_or_else(BridgeError::invalid)?,
            Value::Number(v) if v.as_u64().is_some() => v.to_string().len(),
            _ => return Err(BridgeError::invalid()),
        };
        size = size.checked_add(scalar).ok_or_else(BridgeError::invalid)?;
        if size > REQUEST_LIMIT { return Err(BridgeError::invalid()); }
    }
    if size.saturating_add(name.len()).saturating_add(32) > REQUEST_LIMIT { return Err(BridgeError::invalid()); }
    let exact = |keys: &[&str]| object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key));
    let text = |key: &str| object.get(key).and_then(Value::as_str).ok_or_else(BridgeError::invalid);
    match name {
        "github_connection_status" if object.is_empty() => Ok(Command::Status),
        "github_connection_connect_token" if exact(&["projectId", "repository", "token"]) => {
            let (project_id, repository, token) = (text("projectId")?, text("repository")?, text("token")?);
            if !valid_id(project_id) || !coordinate(repository) || !private_token(token) { return Err(BridgeError::invalid()); }
            Ok(Command::ConnectToken(ConnectTokenArgs { project_id: project_id.into(), repository: repository.into(), token: token.into() }))
        },
        "github_connection_refresh" if exact(&["sessionId", "expectedRevision"]) => {
            let session_id = text("sessionId")?;
            let revision = object.get("expectedRevision").and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok()).filter(|v| *v != 0).ok_or_else(BridgeError::invalid)?;
            if !valid_id(session_id) { return Err(BridgeError::invalid()); }
            Ok(Command::Refresh(RefreshArgs { session_id: session_id.into(), expected_revision: revision }))
        },
        "github_connection_disconnect" if exact(&["sessionId"]) => {
            let session_id = text("sessionId")?;
            if !valid_id(session_id) { return Err(BridgeError::invalid()); }
            Ok(Command::Disconnect(DisconnectArgs { session_id: session_id.into() }))
        },
        _ => Err(BridgeError::invalid()),
    }
}
pub(crate) fn decode_command(name: &str, bytes: &[u8]) -> Result<Command, BridgeError> {
    // Conservative envelope reservation; caller args alone cannot consume 8KiB.
    if bytes.len().saturating_add(name.len()).saturating_add(32) > REQUEST_LIMIT { return Err(BridgeError::invalid()); }
    let value = strict_json(bytes).map_err(|_| BridgeError::invalid())?;
    if !bounds(&value, REQUEST_LIMIT, 128, 6) { return Err(BridgeError::invalid()); }
    match name {
        "github_connection_status" if value.as_object().is_some_and(|v| v.is_empty()) => Ok(Command::Status),
        "github_connection_connect_token" => {
            let v: ConnectTokenArgs = serde_json::from_value(value).map_err(|_| BridgeError::invalid())?;
            if !valid_id(&v.project_id) || !coordinate(&v.repository) || !private_token(&v.token) { return Err(BridgeError::invalid()); }
            Ok(Command::ConnectToken(v))
        },
        "github_connection_refresh" => {
            let v: RefreshArgs = serde_json::from_value(value).map_err(|_| BridgeError::invalid())?;
            if !valid_id(&v.session_id) || v.expected_revision == 0 { return Err(BridgeError::invalid()); }
            Ok(Command::Refresh(v))
        },
        "github_connection_disconnect" => {
            let v: DisconnectArgs = serde_json::from_value(value).map_err(|_| BridgeError::invalid())?;
            if !valid_id(&v.session_id) { return Err(BridgeError::invalid()); }
            Ok(Command::Disconnect(v))
        },
        _ => Err(BridgeError::invalid()),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrivateParams {
    pub(crate) repository: String,
    #[serde(deserialize_with = "nullable")] pub(crate) expected_account_id: Option<String>,
    #[serde(deserialize_with = "nullable")] pub(crate) expected_repository_id: Option<String>,
    pub(crate) token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateRequest { pub(crate) protocol: String, pub(crate) id: String, pub(crate) params: PrivateParams }
pub(crate) fn decode_private_request(bytes: &[u8]) -> Result<PrivateRequest, BridgeError> {
    if bytes.len() > REQUEST_LIMIT { return Err(BridgeError::invalid()); }
    let value = strict_json(bytes).map_err(|_| BridgeError::invalid())?;
    if !bounds(&value, REQUEST_LIMIT, 128, 6) { return Err(BridgeError::invalid()); }
    let request: PrivateRequest = serde_json::from_value(value).map_err(|_| BridgeError::invalid())?;
    let p = &request.params;
    if request.protocol != PRIVATE_PROTOCOL || !valid_id(&request.id) || !coordinate(&p.repository) || !private_token(&p.token)
        || p.expected_account_id.as_ref().is_some_and(|v| !numeric_id(v)) || p.expected_repository_id.as_ref().is_some_and(|v| !numeric_id(v))
        || p.expected_repository_id.is_some() && p.expected_account_id.is_none() { return Err(BridgeError::invalid()); }
    Ok(request)
}

// Dedicated one-buffer encoder. It never constructs a Serialize/Clone/Debug
// request or a generic Value containing the token. Escaping counts toward the
// same total budget, including the final newline.
struct PrivateWriter { bytes: Vec<u8> }
impl PrivateWriter {
    fn append(&mut self, bytes: &[u8]) -> Result<(), BridgeError> {
        if bytes.len() > (REQUEST_LIMIT - 1).saturating_sub(self.bytes.len()) { return Err(BridgeError::invalid()); }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn string(&mut self, text: &str) -> Result<(), BridgeError> {
        self.append(b"\"")?;
        for byte in text.bytes() {
            if matches!(byte, b'"' | b'\\') { self.append(b"\\")?; }
            self.append(&[byte])?;
        }
        self.append(b"\"")
    }
    fn nullable_id(&mut self, value: Option<&str>) -> Result<(), BridgeError> {
        match value { Some(value) => self.string(value), None => self.append(b"null") }
    }
}
pub(crate) fn encode_private_request(id: &str, repository: &str, expected_account_id: Option<&str>,
    expected_repository_id: Option<&str>, token: &str) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !coordinate(repository) || !private_token(token)
        || expected_account_id.is_some_and(|v| !numeric_id(v))
        || expected_repository_id.is_some_and(|v| !numeric_id(v))
        || expected_repository_id.is_some() && expected_account_id.is_none() { return Err(BridgeError::invalid()); }
    let mut writer = PrivateWriter { bytes: Vec::with_capacity(REQUEST_LIMIT) };
    writer.append(b"{\"protocol\":\"mrk-github-readonly/1\",\"id\":")?;
    writer.string(id)?;
    writer.append(b",\"params\":{\"repository\":")?;
    writer.string(repository)?;
    writer.append(b",\"expectedAccountId\":")?;
    writer.nullable_id(expected_account_id)?;
    writer.append(b",\"expectedRepositoryId\":")?;
    writer.nullable_id(expected_repository_id)?;
    writer.append(b",\"token\":")?;
    writer.string(token)?;
    writer.append(b"}}")?;
    writer.bytes.push(b'\n');
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn idle() -> Value {
        let fact = json!({"state":"not-observed","value":null,"observedAt":null,"reason":"not-connected"});
        json!({"schemaVersion":1,"revision":1,"capability":{"readOnlySessionAvailable":false,"reason":"unqualified","deviceLogin":"publisher-unconfigured","storage":"session-only"},
            "session":null,"operation":null,"account":fact.clone(),"repository":fact.clone(),"automation":fact,
            "facts":{"remoteMutationAvailable":false,"dispatchAvailable":false,"repositoryActionsSettingsObservation":"not-run","environmentObservation":"not-run",
                "secretObservation":"not-run","variableObservation":"not-run","protectionObservation":"not-run","runnerObservation":"not-run","templateCompatibility":"unknown","releaseReadiness":"unknown"}})
    }
    fn connected() -> Value {
        // Hypothetical DATA only; this module has no real capability producer.
        let mut value = idle(); value["revision"] = json!(2);
        value["capability"]["readOnlySessionAvailable"] = json!(true); value["capability"]["reason"] = json!("none");
        value["session"] = json!({"id":"s","projectId":"p","targetRepository":"owner/app","state":"connected","expiresAt":"2026-09-17T13:00:00Z"});
        value["operation"] = json!({"id":"op","kind":"connect","phase":"settled","reason":"none"});
        let observed = |row: Value| json!({"state":"observed","value":row,"observedAt":"2026-09-17T12:00:00Z","reason":"none"});
        value["account"] = observed(json!({"id":"11","login":"owner"}));
        value["repository"] = observed(json!({"id":"22","fullName":"owner/app","defaultBranch":"main","visibility":"private","archived":false,
            "permissions":{"pull":"reported-allowed","push":"reported-denied","admin":"unknown"}}));
        let workflows: Vec<Value> = IDS.iter().enumerate().map(|(i, id)| json!({"id":id,"remoteId":(100 + i).to_string(),"presence":"listed","state":"active"})).collect();
        value["automation"] = observed(json!({"coverage":"complete","workflows":workflows}));
        value
    }
    fn accepts(value: &Value) -> bool { decode_status(&serde_json::to_vec(value).unwrap()).is_ok() }
    #[test]
    fn nullable_keys_are_required_and_public_authority_stays_closed() {
        let original = idle(); assert!(accepts(&original));
        for key in ["session", "operation"] {
            let mut v = original.clone(); v.as_object_mut().unwrap().remove(key); assert!(!accepts(&v));
        }
        for key in ["value", "observedAt"] {
            let mut v = original.clone(); v["account"].as_object_mut().unwrap().remove(key); assert!(!accepts(&v));
        }
        for (pointer, value) in [("/revision", json!(true)), ("/revision", json!(0)), ("/facts/dispatchAvailable", json!(true)),
            ("/account/value", json!({"id":"1","login":"inert"}))] {
            let mut v = original.clone(); *v.pointer_mut(pointer).unwrap() = value; assert!(!accepts(&v));
        }
        let mut v = original; v["token"] = json!("INERT_PRIVATE_SENTINEL"); assert!(!accepts(&v));
        assert!(decode_status(b"{\"schemaVersion\":1,\"schemaVersion\":1}").is_err());
    }
    #[test]
    fn observed_graph_requires_parent_facts_expiry_and_nullable_workflow_keys() {
        let original = connected(); assert!(accepts(&original));
        let mut maximum = original.clone(); maximum["account"]["value"]["id"] = json!("18446744073709551615"); assert!(accepts(&maximum));
        for (pointer, key) in [("/session", "expiresAt"), ("/automation/value/workflows/0", "remoteId")] {
            let mut value = original.clone(); value.pointer_mut(pointer).unwrap().as_object_mut().unwrap().remove(key); assert!(!accepts(&value));
        }
        for (pointer, field) in [("/session/expiresAt", Value::Null), ("/account/value/id", json!(11)),
            ("/account/value/login", json!("owner\u{202e}")), ("/repository/value/id", json!("18446744073709551616"))] {
            let mut value = original.clone(); *value.pointer_mut(pointer).unwrap() = field; assert!(!accepts(&value));
        }
        let mut value = original; value["repository"]["state"] = json!("stale"); value["repository"]["reason"] = json!("stale"); assert!(!accepts(&value));
        value["automation"]["state"] = json!("stale"); value["automation"]["reason"] = json!("stale"); assert!(accepts(&value));
    }
    #[test]
    fn dates_identifiers_and_private_requests_are_finite() {
        assert!(utc("2024-02-29T23:59:59Z"));
        for v in ["2025-02-29T00:00:00Z", "2024-01-01T24:00:00Z", "0000-01-01T00:00:00Z", "2024-01-01T00:00:00Z\n"] { assert!(!utc(v)); }
        assert!(numeric_id("18446744073709551615"));
        for v in ["0", "01", "18446744073709551616", "1\n"] { assert!(!numeric_id(v)); }
        let args = json!({"projectId":"p","repository":"owner/app","token":"INERT_PRIVATE_SENTINEL"});
        assert!(decode_command("github_connection_connect_token", &serde_json::to_vec(&args).unwrap()).is_ok());
        let mut bad = args; bad["url"] = json!("https://invalid.example");
        assert!(decode_command("github_connection_connect_token", &serde_json::to_vec(&bad).unwrap()).is_err());
        assert!(decode_command("github_connection_status", b"{}").is_ok());
        assert!(decode_command("github_connection_status", b"{\"token\":\"INERT_PRIVATE_SENTINEL\"}").is_err());
        assert!(decode_command("github_connection_refresh", b"{\"sessionId\":\"s\",\"expectedRevision\":true}").is_err());
        assert!(decode_command("github_connection_dispatch", b"{}").is_err());
        let request = json!({"protocol":PRIVATE_PROTOCOL,"id":"op","params":{"repository":"owner/app","expectedAccountId":null,"expectedRepositoryId":null,"token":"INERT_PRIVATE_SENTINEL"}});
        assert!(decode_private_request(&serde_json::to_vec(&request).unwrap()).is_ok());
        let mut bad = request; bad["params"].as_object_mut().unwrap().remove("expectedRepositoryId");
        assert!(decode_private_request(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    #[test]
    fn rejected_private_data_has_only_fixed_public_diagnostics() {
        const SENTINEL: &str = "INERT_PRIVATE_SENTINEL";
        let args = json!({"projectId":"p","repository":"owner/app","token":SENTINEL,"unexpected":SENTINEL});
        let Err(error) = decode_command("github_connection_connect_token", &serde_json::to_vec(&args).unwrap()) else { panic!("extra field admitted"); };
        assert!(!serde_json::to_string(&error).unwrap().contains(SENTINEL));
        assert!(!format!("{error:?}").contains(SENTINEL));
        let mut public = idle(); public["token"] = json!(SENTINEL);
        let Err(error) = decode_status(&serde_json::to_vec(&public).unwrap()) else { panic!("private field admitted"); };
        assert!(!serde_json::to_string(&error).unwrap().contains(SENTINEL));
    }
    #[test]
    fn workflow_coverage_and_cleanup_graph_are_not_independent_flags() {
        for field in ["repository", "automation"] {
            for state in ["unavailable", "stale"] {
                let mut value = connected();
                for name in ["repository", "automation"] {
                    value[name]["state"] = json!(state);
                    value[name]["reason"] = json!("network-unavailable");
                    if state == "unavailable" { value[name]["value"] = Value::Null; value[name]["observedAt"] = Value::Null; }
                }
                assert!(accepts(&value));
                value[field]["reason"] = json!("cleanup-unknown");
                assert!(!accepts(&value), "cleanup reason without original cleanup graph: {field}/{state}");
            }
        }
        let mut v = idle();
        v["capability"]["reason"] = json!("cleanup-unknown"); assert!(!accepts(&v));
        v["session"] = json!({"id":"s","projectId":"p","targetRepository":"owner/app","state":"cleanup-unknown","expiresAt":null});
        v["operation"] = json!({"id":"op","kind":"disconnect","phase":"cleanup-unknown","reason":"cleanup-unknown"});
        v["capability"]["reason"] = json!("cleanup-unknown"); assert!(accepts(&v));
        v["operation"]["phase"] = json!("settled"); assert!(!accepts(&v));
        let mut rows: Vec<Workflow> = IDS.into_iter().map(|id| Workflow { id, remote_id: None, presence: Presence::Unknown, state: WorkflowState::Unknown }).collect();
        assert!(Automation { coverage: Coverage::Limited, workflows: rows.clone() }.valid());
        assert!(!Automation { coverage: Coverage::Complete, workflows: rows.clone() }.valid());
        rows[0].presence = Presence::NotListed;
        assert!(!Automation { coverage: Coverage::Limited, workflows: rows.clone() }.valid());
        rows[0].presence = Presence::Listed; rows[0].remote_id = Some("1".into());
        rows[1].presence = Presence::Listed; rows[1].remote_id = Some("1".into());
        assert!(!Automation { coverage: Coverage::Limited, workflows: rows }.valid());
    }

    fn private_success() -> Value {
        let status = connected();
        json!({"protocol":PRIVATE_PROTOCOL,"id":"read-1",
            "facts":{"schemaVersion":1,"account":status["account"],"repository":status["repository"],"automation":status["automation"]},
            "control":{"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}})
    }
    fn private_frame(value: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(value).unwrap(); bytes.push(b'\n'); bytes
    }
    fn private_accepts(value: &Value) -> bool { decode_private_response("read-1", &private_frame(value)).is_ok() }
    fn private_failed_fact(at: usize, reason: &str) -> Value {
        let mut value = private_success();
        for (index, name) in ["account", "repository", "automation"].into_iter().enumerate().skip(at) {
            value["facts"][name] = json!({"state":"unavailable","value":null,"observedAt":null,
                "reason":if index == at { reason } else { "cancelled" }});
        }
        value
    }

    #[test]
    fn borrowed_commands_bound_before_secret_copy_without_serializing_raw_ipc() {
        let input = json!({"projectId":"p","repository":"owner/app","token":"INERT_ONLY"});
        assert!(matches!(decode_command_value("github_connection_connect_token", &input), Ok(Command::ConnectToken(_))));
        assert!(matches!(decode_command_value("github_connection_status", &json!({})), Ok(Command::Status)));
        for value in [json!({"projectId":"p","repository":"owner/app","token":true}),
            json!({"projectId":"p","repository":"owner/app","token":{"secret":"INERT_ONLY"}}),
            json!({"projectId":"p","repository":"owner/app","token":"INERT_ONLY","extra":"INERT_ONLY"}),
            json!({"projectId":"p","repository":"owner/app","token":"\"".repeat(4096)})] {
            assert!(decode_command_value("github_connection_connect_token", &value).is_err());
        }
        for revision in [json!(true), json!(0), json!(1.0), json!(4294967296u64)] {
            assert!(decode_command_value("github_connection_refresh", &json!({"sessionId":"s","expectedRevision":revision})).is_err());
        }
        assert!(decode_command_value("github_connection_disconnect", &json!({"sessionId":"s","token":"INERT_ONLY"})).is_err());
    }

    #[test]
    fn private_encoder_preserves_exact_token_and_counts_escaping_and_newline() {
        const INERT: &str = "INERT_\"\\_ONLY";
        let bytes = encode_private_request("read-1", "owner/app", Some("1"), Some("2"), INERT).unwrap();
        assert!(bytes.len() <= REQUEST_LIMIT && bytes.ends_with(b"\n"));
        let request = decode_private_request(&bytes).unwrap();
        assert_eq!(request.id, "read-1");
        assert_eq!(request.params.token, INERT);
        assert_eq!(request.params.expected_repository_id.as_deref(), Some("2"));
        assert!(encode_private_request("read-1", "owner/app", None, None, &"A".repeat(4096)).is_ok());
        assert!(encode_private_request("read-1", "owner/app", None, None, &"\"".repeat(4096)).is_err());
        assert!(encode_private_request("read-1", "owner/app", None, Some("2"), INERT).is_err());
        for token in ["", "INERT\nONLY", "INERT ONLY", "é"] {
            assert!(encode_private_request("read-1", "owner/app", None, None, token).is_err());
        }
    }

    #[test]
    fn private_response_is_one_closed_correlated_fresh_graph() {
        let original = private_success();
        assert!(private_accepts(&original));
        assert!(decode_private_response("other", &private_frame(&original)).is_err());
        for key in ["protocol", "id", "facts", "control"] {
            let mut value = original.clone(); value.as_object_mut().unwrap().remove(key);
            assert!(!private_accepts(&value));
        }
        for key in ["credentialExpiresAt", "cooldownSeconds", "cooldownBlocked"] {
            let mut value = original.clone(); value["control"].as_object_mut().unwrap().remove(key);
            assert!(!private_accepts(&value));
        }
        for state in ["stale", "not-observed"] {
            let mut value = original.clone();
            value["facts"]["account"]["state"] = json!(state);
            value["facts"]["account"]["reason"] = json!("cancelled");
            assert!(!private_accepts(&value));
        }
        let mut value = original.clone();
        value["facts"]["automation"] = json!({"state":"unavailable","value":null,"observedAt":null,"reason":"forbidden"});
        assert!(!private_accepts(&value)); // None cannot hide a failed component.
        value["control"]["reason"] = json!("forbidden");
        assert!(private_accepts(&value)); // Earlier observations remain private data.
        value["facts"]["repository"]["state"] = json!("unavailable");
        assert!(!private_accepts(&value)); // Unavailable is not an independent flag.
    }

    #[test]
    fn private_control_keeps_known_delays_through_invalid_expiry_refusal() {
        for reason in ["rate-limited", "response-invalid"] {
            for seconds in [1, 60, 7200, COOLDOWN_MAX_SECONDS] {
                let mut value = private_success();
                value["control"]["reason"] = json!(reason);
                value["control"]["cooldownSeconds"] = json!(seconds);
                assert!(private_accepts(&value));
                value["control"]["cooldownBlocked"] = json!(true);
                assert!(!private_accepts(&value));
            }
            let mut value = private_success();
            value["control"]["reason"] = json!(reason);
            value["control"]["cooldownBlocked"] = json!(true);
            assert!(private_accepts(&value));
        }
        for seconds in [json!(true), json!(0), json!(-1), json!(1.0), json!(604801)] {
            let mut value = private_success();
            value["control"]["reason"] = json!("rate-limited");
            value["control"]["cooldownSeconds"] = seconds;
            assert!(!private_accepts(&value));
        }
        let mut value = private_success();
        value["control"]["reason"] = json!("rate-limited");
        assert!(!private_accepts(&value));
        value["control"]["reason"] = json!("response-invalid");
        assert!(private_accepts(&value)); // No new hint must not reset old state.
        for reason in ["none", "forbidden", "unauthorized", "cancelled"] {
            value["control"]["reason"] = json!(reason);
            value["control"]["cooldownSeconds"] = json!(60);
            assert!(!private_accepts(&value));
        }
        for reason in ["busy", "unqualified", "cleanup-unknown", "stale"] {
            let mut value = private_success(); value["control"]["reason"] = json!(reason);
            assert!(!private_accepts(&value));
        }
    }

    #[test]
    fn private_fact_vetoes_cannot_hide_under_retryable_control() {
        // Valid individual facts/controls, deliberately contradictory as a whole.
        // The actual decoder must reject the entire envelope, including a valid
        // supplied cooldown, rather than handing any partial outcome to a session.
        for at in 0..3 {
            for fact_reason in ["unauthorized", "target-changed", "response-invalid", "expired", "rate-limited"] {
                for control_reason in ["none", "forbidden", "not-found-or-inaccessible", "network-unavailable", "tls-failed", "response-limit"] {
                    let mut value = private_failed_fact(at, fact_reason);
                    value["control"]["reason"] = json!(control_reason);
                    assert_eq!(decode_private_response("read-1", &private_frame(&value)).unwrap_err(), BridgeError::protocol());
                }
            }
            for fact_reason in ["unauthorized", "target-changed", "response-invalid", "expired"] {
                let mut value = private_failed_fact(at, fact_reason);
                value["control"]["reason"] = json!("rate-limited");
                value["control"]["cooldownSeconds"] = json!(7200);
                assert_eq!(decode_private_response("read-1", &private_frame(&value)).unwrap_err(), BridgeError::protocol());
            }
            let mut value = private_failed_fact(at, "rate-limited");
            value["control"]["reason"] = json!("response-invalid");
            assert_eq!(decode_private_response("read-1", &private_frame(&value)).unwrap_err(), BridgeError::protocol());
        }
        for (fact_reason, control_reason) in [("unauthorized", "cancelled"), ("target-changed", "unauthorized"),
            ("response-invalid", "expired"), ("expired", "target-changed"), ("rate-limited", "unauthorized")] {
            let mut value = private_failed_fact(0, fact_reason);
            value["control"]["reason"] = json!(control_reason);
            assert_eq!(decode_private_response("read-1", &private_frame(&value)).unwrap_err(), BridgeError::protocol());
        }
    }

    #[test]
    fn private_coherence_keeps_dominating_refusal_partial_facts_and_final_rate_limit() {
        // These are supplied grammar DATA, not evidence that a read, timeout or
        // credential expiry occurred. Expired is not a helper-budget inference.
        for at in 0..3 {
            for fact_reason in ["unauthorized", "target-changed", "response-invalid", "expired"] {
                for control_reason in [fact_reason, "response-invalid"] {
                    let mut value = private_failed_fact(at, fact_reason);
                    value["control"]["reason"] = json!(control_reason);
                    assert!(private_accepts(&value));
                    if control_reason == "response-invalid" {
                        value["control"]["cooldownSeconds"] = json!(7200);
                        assert!(private_accepts(&value));
                        value["control"]["cooldownSeconds"] = Value::Null;
                        value["control"]["cooldownBlocked"] = json!(true);
                        assert!(private_accepts(&value));
                    }
                }
            }
            for control_reason in ["rate-limited", "response-invalid"] {
                let mut value = private_failed_fact(at, "rate-limited");
                value["control"]["reason"] = json!(control_reason);
                value["control"]["cooldownSeconds"] = json!(60);
                assert!(private_accepts(&value));
                value["control"]["cooldownSeconds"] = Value::Null;
                value["control"]["cooldownBlocked"] = json!(true);
                assert!(private_accepts(&value));
            }
        }
        let mut partial = private_failed_fact(2, "forbidden"); // Account/repository bracket succeeded.
        partial["control"]["reason"] = json!("forbidden");
        assert!(private_accepts(&partial));
        let mut skipped = private_failed_fact(1, "cancelled"); // An unsent bracket is not the stopping cause.
        skipped["control"]["reason"] = json!("unauthorized");
        assert!(private_accepts(&skipped));
        let mut complete = private_success(); // The final HTTP200 can exhaust quota.
        complete["control"]["reason"] = json!("rate-limited");
        complete["control"]["cooldownSeconds"] = json!(7200);
        assert!(private_accepts(&complete));
        complete["control"]["cooldownSeconds"] = Value::Null;
        complete["control"]["cooldownBlocked"] = json!(true);
        assert!(private_accepts(&complete));
    }

    #[test]
    fn private_frame_diagnostics_never_echo_arbitrary_control_or_header_data() {
        const SENTINEL: &str = "INERT_PRIVATE_SENTINEL";
        let mut value = private_success(); value["control"]["rawHeader"] = json!(SENTINEL);
        let error = decode_private_response("read-1", &private_frame(&value)).unwrap_err();
        assert!(!format!("{error:?}").contains(SENTINEL));
        let original = private_success();
        let mut frame = private_frame(&original); frame.pop();
        assert!(decode_private_response("read-1", &frame).is_err());
        frame.push(b'\n'); frame.push(b'\n');
        assert!(decode_private_response("read-1", &frame).is_err());
        assert!(decode_private_response("read-1", b"{\"protocol\":1,\"protocol\":1}\n").is_err());
        assert!(decode_private_response("read-1", &vec![b' '; RESPONSE_LIMIT + 1]).is_err());
        for expiry in ["2025-02-29T00:00:00Z", "2026-09-17 00:00:00 UTC", "2026-09-17T00:00:00+00:00"] {
            let mut value = original.clone(); value["control"]["credentialExpiresAt"] = json!(expiry);
            assert!(!private_accepts(&value));
        }
        // Reserved canonical data syntax only, not a supported server-header
        // grammar or evidence of a token usable with the live helper.
        let mut value = original; value["control"]["credentialExpiresAt"] = json!("2026-09-17T00:00:00Z");
        assert!(private_accepts(&value));
    }
}
