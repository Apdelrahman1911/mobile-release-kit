//! Closed nonpublishing preflight DTOs. This module owns no credential, consent,
//! filesystem, process, timer or network capability. A parsed record is DATA.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use crate::{error::BridgeError, github_connection_protocol::{bounds, coordinate, nullable,
    numeric_id, utc, GitHubReadControl}, protocol::{strict_json, valid_id}};

pub(crate) const PROTOCOL: &str = "mrk-github-preflight/1";
pub(crate) const EVENT: &str = "github-preflight-status";
pub(crate) const INITIAL_LIMIT: usize = 16 * 1024;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const GO_LIMIT: usize = 8 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 256 * 1024;
pub(crate) const RECORD_LIMIT: usize = 64;
pub(crate) const TOOLING_REPOSITORY: &str = "Apdelrahman1911/mobile-release-kit";
pub(crate) const WORKFLOW_PATH: &str = ".github/workflows/mobile-preflight.yml";
pub(crate) const ASSURANCE: &str = "github-workflow-observation-not-release-evidence";
pub(crate) const TOOLING_SHA: Option<&str> = option_env!("MRK_GITHUB_PREFLIGHT_TOOLING_SHA");
pub(crate) const CALLER_SHA256: Option<&str> = option_env!("MRK_GITHUB_PREFLIGHT_CALLER_SHA256");

pub(crate) fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn branch(value: &str) -> bool {
    !value.is_empty() && value.len() <= 200 && !value.starts_with("refs/") && !value.contains("..")
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && value.split('/').count() <= 16 && value.split('/').all(|s|
            !s.is_empty() && !s.starts_with('.') && !s.ends_with('.') && !s.ends_with(".lock"))
}
pub(crate) fn publisher_bound() -> bool {
    TOOLING_SHA.is_some_and(|v| hex(v, 40)) && CALLER_SHA256.is_some_and(|v| hex(v, 64))
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform { Android, Ios, Both }
impl Platform { pub(crate) fn text(self) -> &'static str { match self { Self::Android => "android", Self::Ios => "ios", Self::Both => "both" } } }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind { Prepare, Dispatch, Track, Reconcile, Pending }
impl Kind {
    fn journal(self) -> &'static str { match self {
        Self::Prepare => "not-applicable", Self::Dispatch => "durable-intent",
        Self::Track | Self::Reconcile => "matched-intent", Self::Pending => "loaded",
    } }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Effect { None, NotSent, PotentiallyApplied, Accepted }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason { None, Unqualified, PublisherUnconfigured, NotConnected, Busy, InvalidInput,
    TargetChanged, Expired, RateLimited, Cancelled, CleanupUnknown, RuntimeUnavailable, ConsentExpired,
    CallerMismatch, WorkflowUnavailable, SourceChanged, UnresolvedRun, AmbiguousRun, RunChanged,
    JobsIncomplete, Unauthorized, Forbidden, NotFoundOrInaccessible, NetworkUnavailable, TlsFailed,
    ResponseInvalid, ResponseLimit }
impl Reason {
    pub(crate) fn private(self) -> bool { !matches!(self, Self::Unqualified | Self::PublisherUnconfigured | Self::NotConnected
        | Self::Busy | Self::InvalidInput | Self::CleanupUnknown | Self::RuntimeUnavailable | Self::ConsentExpired) }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) project_binding: String, pub(crate) repository: String,
    pub(crate) account_id: String, pub(crate) repository_id: String, pub(crate) branch: String,
    pub(crate) tooling_repository: String, pub(crate) tooling_sha: String,
    pub(crate) platform: Platform, pub(crate) marker: String,
}
impl Target {
    pub(crate) fn valid(&self) -> bool {
        hex(&self.project_binding, 64) && coordinate(&self.repository) && numeric_id(&self.account_id)
            && numeric_id(&self.repository_id) && branch(&self.branch) && self.tooling_repository == TOOLING_REPOSITORY
            && hex(&self.tooling_sha, 40) && hex(&self.marker, 32)
    }
    pub(crate) fn publisher_bound(&self) -> bool { self.valid() && TOOLING_SHA == Some(self.tooling_sha.as_str()) && publisher_bound() }
    pub(crate) fn title(&self) -> String { format!("MRK Desktop preflight [{}]", self.marker) }
    pub(crate) fn full_ref(&self) -> String { format!("refs/heads/{}", self.branch) }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Prepared {
    pub(crate) target: Target, pub(crate) source_sha: String, pub(crate) workflow_id: String,
    pub(crate) workflow_path: String, pub(crate) caller_sha256: String, pub(crate) observed_at: String,
    pub(crate) expected_ref: String, pub(crate) display_title: String, pub(crate) confirmation: String,
}
impl Prepared {
    pub(crate) fn valid(&self) -> bool {
        self.target.valid() && hex(&self.source_sha, 40) && numeric_id(&self.workflow_id) && self.workflow_path == WORKFLOW_PATH
            && hex(&self.caller_sha256, 64) && utc(&self.observed_at) && self.expected_ref == self.target.full_ref()
            && self.display_title == self.target.title() && self.confirmation == format!(
                "Run credential-free {} preflight for {} at {}? This may build project code, download dependencies, use GitHub-hosted minutes and upload diagnostic reports. The reviewed canonical workflow does not sign, upload to a Store or publish a release. GitHub dispatch uses this mutable branch, not an atomic commit lock. Authorized writers can replace its workflow after review; use a trusted protected branch.",
                self.target.platform.text(), self.target.repository, self.source_sha)
    }
    pub(crate) fn publisher_bound(&self) -> bool {
        self.valid() && self.target.publisher_bound() && CALLER_SHA256 == Some(self.caller_sha256.as_str())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind: Kind, pub(crate) target: Target,
    #[serde(deserialize_with = "nullable")] pub(crate) prepared: Option<Prepared>,
    #[serde(deserialize_with = "nullable")] pub(crate) run_id: Option<String>,
}
impl Action {
    pub(crate) fn valid(&self) -> bool {
        self.kind != Kind::Pending && self.target.valid() && (self.kind == Kind::Prepare) == self.prepared.is_none()
            && self.prepared.as_ref().is_none_or(|v| v.valid() && v.target == self.target)
            && (self.kind == Kind::Track) == self.run_id.is_some() && self.run_id.as_ref().is_none_or(|v| numeric_id(v))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Scope { pub(crate) project_binding: String, pub(crate) repository: String,
    pub(crate) account_id: String, pub(crate) repository_id: String }
impl Scope {
    pub(crate) fn valid(&self) -> bool { hex(&self.project_binding, 64) && coordinate(&self.repository)
        && numeric_id(&self.account_id) && numeric_id(&self.repository_id) }
    pub(crate) fn matches(&self, target: &Target) -> bool { self.project_binding == target.project_binding
        && self.repository == target.repository && self.account_id == target.account_id && self.repository_id == target.repository_id }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingRecord { pub(crate) prepared: Prepared,
    #[serde(deserialize_with = "nullable")] pub(crate) run_id: Option<String> }
impl PendingRecord { pub(crate) fn valid(&self) -> bool { self.prepared.valid() && self.run_id.as_ref().is_none_or(|v| numeric_id(v)) } }

// This is nonsecret request DATA. Home can only be supplied by native account
// selection, not by any public command decoder or renderer DTO.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Request { pub(crate) action: Option<Action>, pub(crate) pending_scope: Option<Scope>, pub(crate) home: Option<String> }
impl Request {
    pub(crate) fn kind(&self) -> Kind { self.action.as_ref().map_or(Kind::Pending, |v| v.kind) }
    pub(crate) fn valid(&self) -> bool {
        self.action.is_some() != self.pending_scope.is_some() && self.action.as_ref().is_none_or(Action::valid)
            && self.pending_scope.as_ref().is_none_or(Scope::valid) && (self.kind() == Kind::Prepare) == self.home.is_none()
            && self.home.as_ref().is_none_or(|v| v.starts_with('/') && v.len() <= 4016 && !v.bytes().any(|b| b < 32 || b == 127))
    }
}
pub(crate) fn encode_initial(id: &str, request: &Request) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !request.valid() { return Err(BridgeError::invalid()); }
    let value = serde_json::json!({"protocol": PROTOCOL, "id": id, "action": request.action,
        "pendingScope": request.pending_scope, "home": request.home});
    let mut raw = serde_json::to_vec(&value).map_err(|_| BridgeError::invalid())?; raw.push(b'\n');
    if raw.len() > INITIAL_LIMIT { return Err(BridgeError::invalid()); } Ok(raw)
}
pub(crate) fn request_digest(raw: &[u8]) -> String { format!("{:x}", Sha256::digest(raw)) }
fn frame(raw: &[u8], limit: usize, nodes: usize, depth: usize) -> Result<Value, BridgeError> {
    if raw.len() < 3 || raw.len() > limit || !raw.ends_with(b"\n") { return Err(BridgeError::protocol()); }
    let body = &raw[..raw.len() - 1];
    if body.first() != Some(&b'{') || body.last() != Some(&b'}') || body.iter().any(|b| matches!(b, b'\n' | b'\r')) {
        return Err(BridgeError::protocol());
    }
    let value = strict_json(body)?;
    if !bounds(&value, limit, nodes, depth) { return Err(BridgeError::protocol()); } Ok(value)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready { request_sha256: String, journal: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyEnvelope { protocol: String, id: String, ready: Ready }
pub(crate) fn decode_ready(raw: &[u8], id: &str, digest: &str, kind: Kind) -> Result<(), BridgeError> {
    let value: ReadyEnvelope = serde_json::from_value(frame(raw, READY_LIMIT, 32, 4)?).map_err(|_| BridgeError::protocol())?;
    if value.protocol != PROTOCOL || value.id != id || value.ready.request_sha256 != digest || value.ready.journal != kind.journal() {
        return Err(BridgeError::protocol());
    } Ok(())
}
pub(crate) fn encode_go(id: &str, digest: &str, token: Option<&str>, kind: Kind) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !hex(digest, 64) || (kind == Kind::Pending) != token.is_none()
        || token.is_some_and(|v| v.is_empty() || v.len() > 4096 || !v.bytes().all(|b| (0x21..=0x7e).contains(&b))) {
        return Err(BridgeError::invalid());
    }
    // One private writer buffer. No Value/token DTO, Debug or serialized public
    // request can accidentally retain a credential copy.
    let mut raw = Vec::with_capacity(GO_LIMIT);
    raw.extend_from_slice(b"{\"protocol\":\"mrk-github-preflight/1\",\"id\":");
    serde_json::to_writer(&mut raw, id).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b",\"go\":{\"requestSha256\":");
    serde_json::to_writer(&mut raw, digest).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b",\"token\":");
    serde_json::to_writer(&mut raw, &token).map_err(|_| BridgeError::invalid())?;
    raw.extend_from_slice(b"}}\n");
    if raw.len() > GO_LIMIT { return Err(BridgeError::invalid()); } Ok(raw)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunStatus { Queued, InProgress, Completed, Waiting, Pending, Requested }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Conclusion { Success, Failure, Neutral, Cancelled, Skipped, TimedOut, ActionRequired, Stale, StartupFailure }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum JobKind { InputGuard, Android, Ios }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Job { pub(crate) id: String, pub(crate) kind: JobKind, pub(crate) status: RunStatus,
    #[serde(deserialize_with = "nullable")] pub(crate) conclusion: Option<Conclusion> }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Run { pub(crate) id: String, pub(crate) attempt: u32, pub(crate) status: RunStatus,
    #[serde(deserialize_with = "nullable")] pub(crate) conclusion: Option<Conclusion>,
    pub(crate) observed_at: String, pub(crate) jobs: Vec<Job>, pub(crate) url: String, pub(crate) assurance: String }
impl Run {
    pub(crate) fn valid(&self, prepared: &Prepared) -> bool {
        let mut ids = std::collections::BTreeSet::new(); let mut kinds = std::collections::BTreeSet::new();
        numeric_id(&self.id) && self.attempt == 1 && (self.status == RunStatus::Completed) == self.conclusion.is_some()
            && utc(&self.observed_at) && self.assurance == ASSURANCE && self.jobs.len() <= 3
            && self.url == format!("https://github.com/{}/actions/runs/{}", prepared.target.repository, self.id)
            && self.jobs.iter().all(|row| numeric_id(&row.id) && ids.insert(&row.id) && kinds.insert(row.kind)
                && (row.status == RunStatus::Completed) == row.conclusion.is_some())
            && (self.conclusion != Some(Conclusion::Success) || [JobKind::InputGuard, JobKind::Android, JobKind::Ios].iter()
                .filter(|kind| **kind == JobKind::InputGuard || prepared.target.platform == Platform::Both
                    || **kind == JobKind::Android && prepared.target.platform == Platform::Android
                    || **kind == JobKind::Ios && prepared.target.platform == Platform::Ios)
                .all(|kind| self.jobs.iter().any(|row| row.kind == *kind && row.status == RunStatus::Completed
                    && row.conclusion == Some(Conclusion::Success))))
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Outcome {
    pub(crate) schema_version: u32, pub(crate) action: Kind, pub(crate) reason: Reason, pub(crate) effect: Effect,
    #[serde(deserialize_with = "nullable")] pub(crate) prepared: Option<Prepared>,
    #[serde(deserialize_with = "nullable")] pub(crate) run_id: Option<String>,
    #[serde(deserialize_with = "nullable")] pub(crate) run: Option<Run>, pub(crate) control: GitHubReadControl,
}
impl Outcome {
    pub(crate) fn valid(&self, request: &Request) -> bool {
        let Some(action) = &request.action else { return false; };
        if self.schema_version != 1 || self.action != action.kind || !self.reason.private() || !self.control.valid()
            || self.run_id.as_ref().is_some_and(|v| !numeric_id(v)) { return false; }
        // Header credential/cooldown controls are never hidden by a nicer action
        // result. The policy's domain refusals legitimately retain control:none.
        if self.control.reason != crate::github_connection_protocol::Reason::None {
            let expected = serde_json::to_value(self.control.reason).ok();
            if expected != serde_json::to_value(self.reason).ok() { return false; }
        }
        match self.action {
            Kind::Prepare => self.effect == Effect::None && self.run_id.is_none() && self.run.is_none()
                && (self.reason == Reason::None) == self.prepared.is_some()
                && self.prepared.as_ref().is_none_or(|v| v.publisher_bound() && v.target == action.target),
            Kind::Dispatch => self.prepared.is_none() && self.run.is_none() && self.effect != Effect::None
                && (self.effect == Effect::Accepted) == (self.reason == Reason::None)
                && (self.effect == Effect::Accepted) == self.run_id.is_some(),
            Kind::Track | Kind::Reconcile => self.effect == Effect::None && self.prepared.is_none()
                && (self.reason == Reason::None) == self.run.is_some() && self.run.is_some() == self.run_id.is_some()
                && self.run.as_ref().is_none_or(|run| action.prepared.as_ref().is_some_and(|prepared|
                    run.valid(prepared) && Some(&run.id) == self.run_id.as_ref()
                        && action.run_id.as_ref().is_none_or(|id| id == &run.id))),
            Kind::Pending => false,
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply {
    protocol: String, id: String,
    #[serde(deserialize_with = "nullable")] pub(crate) result: Option<Outcome>,
    #[serde(deserialize_with = "nullable")] pub(crate) pending: Option<Vec<PendingRecord>>,
}
pub(crate) fn decode_reply(id: &str, raw: &[u8], request: &Request) -> Result<Reply, BridgeError> {
    let reply: Reply = serde_json::from_value(frame(raw, RESPONSE_LIMIT, 20_000, 16)?).map_err(|_| BridgeError::protocol())?;
    if reply.protocol != PROTOCOL || reply.id != id || !request.valid() { return Err(BridgeError::protocol()); }
    if let Some(scope) = &request.pending_scope {
        let Some(records) = &reply.pending else { return Err(BridgeError::protocol()); };
        let mut seen = std::collections::BTreeSet::new();
        if reply.result.is_some() || records.len() > RECORD_LIMIT || !records.iter().all(|row|
            row.valid() && row.prepared.publisher_bound() && scope.matches(&row.prepared.target)
                && seen.insert(&row.prepared.target.marker)) { return Err(BridgeError::protocol()); }
    } else if reply.pending.is_some() || !reply.result.as_ref().is_some_and(|v| v.valid(request)) { return Err(BridgeError::protocol()); }
    Ok(reply)
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase { Running, Settled, CleanupUnknown }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operation { pub(crate) id: String, pub(crate) kind: Kind, pub(crate) phase: Phase,
    pub(crate) reason: Reason, pub(crate) effect: Effect }
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u32, pub(crate) revision: u32, pub(crate) session_id: Option<String>,
    pub(crate) available: bool, pub(crate) reason: Reason, pub(crate) operation: Option<Operation>,
    pub(crate) prepared: Option<Prepared>, pub(crate) consent_expires_at: Option<String>,
    pub(crate) pending: Vec<PendingRecord>, pub(crate) run: Option<Run>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ControlArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32 }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrepareArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32, pub(crate) branch: String, pub(crate) platform: Platform }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DispatchArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32,
    pub(crate) consent_id: String, pub(crate) confirm: bool }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObserveArgs { pub(crate) session_id: String, pub(crate) expected_revision: u32, pub(crate) marker: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CancelArgs { pub(crate) operation_id: String }
pub(crate) enum Command { Status, Prepare(PrepareArgs), Dispatch(DispatchArgs), Track(ObserveArgs), Reconcile(ObserveArgs), Pending(ControlArgs), Cancel(CancelArgs) }
pub(crate) fn decode_command(name: &str, value: &Value) -> Result<Command, BridgeError> {
    // All public requests are tiny flat nonsecret scalars. Refuse a huge string
    // or nested Value before a serializer can allocate its representation.
    let object = value.as_object().filter(|v| v.len() <= 5).ok_or_else(BridgeError::invalid)?;
    if object.iter().any(|(key, value)| key.len() > 32 || match value {
        Value::String(text) => text.len() > 256, Value::Bool(_) => false,
        Value::Number(number) => number.as_u64().is_none(), _ => true,
    }) { return Err(BridgeError::invalid()); }
    if !bounds(value, 2048, 32, 2) { return Err(BridgeError::invalid()); }
    fn read<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, BridgeError> {
        serde_json::from_value(value.clone()).map_err(|_| BridgeError::invalid())
    }
    let command = match name {
        "github_preflight_status" if value.as_object().is_some_and(|v| v.is_empty()) => Command::Status,
        "github_preflight_prepare" => { let v: PrepareArgs = read(value)?;
            if !valid_id(&v.session_id) || v.expected_revision == 0 || v.expected_connection_revision == 0 || !branch(&v.branch) { return Err(BridgeError::invalid()); }
            Command::Prepare(v) },
        "github_preflight_dispatch" => { let v: DispatchArgs = read(value)?;
            if !valid_id(&v.session_id) || v.expected_revision == 0 || !hex(&v.consent_id, 32) || !v.confirm { return Err(BridgeError::invalid()); }
            Command::Dispatch(v) },
        "github_preflight_track" | "github_preflight_reconcile" => { let v: ObserveArgs = read(value)?;
            if !valid_id(&v.session_id) || v.expected_revision == 0 || !hex(&v.marker, 32) { return Err(BridgeError::invalid()); }
            if name == "github_preflight_track" { Command::Track(v) } else { Command::Reconcile(v) } },
        "github_preflight_pending" => { let v: ControlArgs = read(value)?;
            if !valid_id(&v.session_id) || v.expected_revision == 0 { return Err(BridgeError::invalid()); }
            Command::Pending(v) },
        "github_preflight_cancel" => { let v: CancelArgs = read(value)?;
            if !valid_id(&v.operation_id) { return Err(BridgeError::invalid()); } Command::Cancel(v) },
        _ => return Err(BridgeError::invalid()),
    }; Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_commands_cannot_choose_token_endpoint_home_or_toolkit_pin() {
        let original = serde_json::json!({"sessionId":"github-session-1", "expectedRevision":1,
            "expectedConnectionRevision":2,"branch":"release/ui","platform":"android"});
        assert!(decode_command("github_preflight_prepare", &original).is_ok());
        for key in ["token", "url", "home", "toolingSha", "runId", "retry"] {
            let mut value = original.clone(); value[key] = Value::String("INERT".into());
            assert!(decode_command("github_preflight_prepare", &value).is_err());
        }
        for branch in ["refs/heads/main", "a..b", "-a", "a/.b", "a.lock", "a//b"] { assert!(!super::branch(branch)); }
        assert!(super::branch("release/ui"));
    }
    #[test]
    fn ready_go_are_exact_and_pending_has_no_credential() {
        let digest = "d".repeat(64);
        let raw = format!("{{\"protocol\":\"{PROTOCOL}\",\"id\":\"preflight-1\",\"ready\":{{\"requestSha256\":\"{digest}\",\"journal\":\"durable-intent\"}}}}\n");
        assert!(decode_ready(raw.as_bytes(), "preflight-1", &digest, Kind::Dispatch).is_ok());
        assert!(decode_ready(raw.as_bytes(), "preflight-1", &digest, Kind::Prepare).is_err());
        assert!(decode_ready(format!("{raw}{raw}").as_bytes(), "preflight-1", &digest, Kind::Dispatch).is_err());
        assert!(encode_go("preflight-1", &digest, None, Kind::Pending).is_ok());
        assert!(encode_go("preflight-1", &digest, Some("INERT"), Kind::Pending).is_err());
        assert!(encode_go("preflight-1", &digest, None, Kind::Dispatch).is_err());
        assert!(encode_go("preflight-1", &digest, Some("INERT\n"), Kind::Dispatch).is_err());
        assert!(encode_go("preflight-1", &digest, Some(&"\\".repeat(4096)), Kind::Dispatch).is_err());
    }
}
