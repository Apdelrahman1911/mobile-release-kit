//! G1A closed wire only. Registered as a pure module, never an invoke handler.
//! No native service, credential acquisition, transport, timers or gate activation.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use crate::{error::BridgeError, github_workflow_edit_protocol::WorkflowId,
    protocol::{strict_json, valid_id}};

pub const EVENT: &str = "github-connection-status";
pub const PRIVATE_PROTOCOL: &str = "mrk-github-readonly/1";
pub const STATUS_LIMIT: usize = 64 * 1024;
pub const REQUEST_LIMIT: usize = 8 * 1024;
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
}
