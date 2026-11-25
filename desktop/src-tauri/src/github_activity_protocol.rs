//! Closed Activity DATA: PR/Actions metadata, never approval or release authority.
use crate::{
    error::BridgeError,
    github_connection_protocol::{bounds, nullable, numeric_id, utc, GitHubReadControl},
    github_preflight_protocol::{branch as valid_branch, hex},
    github_repository_create_protocol::coordinate,
    protocol::{strict_json, valid_id},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub(crate) const PROTOCOL: &str = "mrk-github-activity/1";
pub(crate) const EVENT: &str = "github-activity-status";
pub(crate) const INITIAL_LIMIT: usize = 8192;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const GO_LIMIT: usize = 8192;
pub(crate) const RESPONSE_LIMIT: usize = 128 * 1024;
pub(crate) const RETAINED_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const LAST_REVISION: u32 = u32::MAX - 1;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Reason {
    None,
    InvalidInput,
    TargetChanged,
    SelectionChanged,
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
    ResourcesUnavailable,
    RuntimeUnavailable,
    Unqualified,
    NotConnected,
    Busy,
    CleanupUnknown,
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
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) project_binding: String,
    pub(crate) repository: String,
    pub(crate) account_id: String,
    pub(crate) repository_id: String,
}
impl Target {
    pub(crate) fn valid(&self) -> bool {
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
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Selection {
    Overview {
        #[serde(deserialize_with = "nullable")]
        branch: Option<String>,
    },
    PullRequest {
        number: String,
    },
    WorkflowRun {
        #[serde(rename = "runId")]
        run_id: String,
        attempt: u32,
    },
}
impl Selection {
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Overview { branch } => branch.as_ref().is_none_or(|v| valid_branch(v)),
            Self::PullRequest { number } => numeric_id(number),
            Self::WorkflowRun { run_id, attempt } => {
                numeric_id(run_id) && (1..=1000).contains(attempt)
            }
        }
    }
    fn heap(&self) -> usize {
        match self {
            Self::Overview { branch } => branch.as_ref().map_or(0, String::capacity),
            Self::PullRequest { number } => number.capacity(),
            Self::WorkflowRun { run_id, .. } => run_id.capacity(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) target: Target,
    pub(crate) selection: Selection,
}
impl Request {
    pub(crate) fn valid(&self) -> bool {
        self.target.valid() && self.selection.valid()
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        self.target.heap()?.checked_add(self.selection.heap())
    }
}
fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>, BridgeError> {
    serde_json::to_value(v)
        .and_then(|v| serde_json::to_vec(&v))
        .map_err(|_| BridgeError::protocol())
}
fn frame(raw: &[u8], limit: usize, nodes: usize) -> Result<Value, BridgeError> {
    if raw.is_empty()
        || raw.len() > limit
        || raw.last() != Some(&b'\n')
        || raw[..raw.len() - 1].contains(&b'\n')
    {
        return Err(BridgeError::protocol());
    }
    let v = strict_json(&raw[..raw.len() - 1])?;
    if !bounds(&v, limit, nodes, 12) {
        return Err(BridgeError::protocol());
    }
    Ok(v)
}
pub(crate) fn encode_initial(id: &str, r: &Request) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id) || !r.valid() {
        return Err(BridgeError::invalid());
    }
    let mut bytes = canonical(&serde_json::json!({"protocol":PROTOCOL,"id":id,"action":r}))?;
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
pub(crate) fn encode_go(
    id: &str,
    digest: &str,
    token: &str,
    r: &Request,
) -> Result<Vec<u8>, BridgeError> {
    if !valid_id(id)
        || !hex(digest, 64)
        || !r.valid()
        || token.is_empty()
        || token.len() > 4096
        || !token.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(BridgeError::invalid());
    }
    // Stream the existing private token directly into its original finite pipe.
    let mut b = Vec::with_capacity(GO_LIMIT);
    b.extend_from_slice(b"{\"protocol\":\"mrk-github-activity/1\",\"id\":");
    serde_json::to_writer(&mut b, id).map_err(|_| BridgeError::invalid())?;
    b.extend_from_slice(b",\"go\":{\"requestSha256\":");
    serde_json::to_writer(&mut b, digest).map_err(|_| BridgeError::invalid())?;
    b.extend_from_slice(b",\"token\":");
    serde_json::to_writer(&mut b, token).map_err(|_| BridgeError::invalid())?;
    b.extend_from_slice(b"}}\n");
    if b.len() > GO_LIMIT {
        use zeroize::Zeroize;
        b.zeroize();
        return Err(BridgeError::invalid());
    }
    Ok(b)
}
fn keys(v: &Value, ks: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == ks.len() && ks.iter().all(|k| o.contains_key(*k)))
}
fn text(v: &Value, n: usize) -> bool {
    v.as_str().is_some_and(|s|!s.trim().is_empty()&&s.len()<=n&&!s.chars().any(|c|c.is_control()||matches!(c,
    '\u{ad}'|'\u{600}'..='\u{605}'|'\u{61c}'|'\u{6dd}'|'\u{70f}'|'\u{890}'..='\u{891}'|'\u{8e2}'|'\u{180e}'|
    '\u{200b}'..='\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2060}'..='\u{2064}'|'\u{2066}'..='\u{206f}'|'\u{feff}'|
    '\u{fff9}'..='\u{fffb}'|'\u{110bd}'|'\u{110cd}'|'\u{13430}'..='\u{1343f}'|'\u{1bca0}'..='\u{1bca3}'|
    '\u{1d173}'..='\u{1d17a}'|'\u{e0001}'|'\u{e0020}'..='\u{e007f}')))
}
fn number(v: &Value) -> bool {
    v.as_str().is_some_and(numeric_id)
}
fn sha(v: &Value) -> bool {
    v.as_str().is_some_and(|s| hex(s, 40))
}
fn time(v: &Value) -> bool {
    v.as_str().is_some_and(utc)
}
fn count(v: &Value) -> bool {
    v.as_u64().is_some_and(|n| n <= i32::MAX as u64)
}
fn one(v: &Value, options: &[&str]) -> bool {
    v.as_str().is_some_and(|s| options.contains(&s))
}
fn status(v: &Value) -> bool {
    one(
        &v["status"],
        &[
            "queued",
            "in_progress",
            "completed",
            "waiting",
            "pending",
            "requested",
        ],
    ) && (v["conclusion"].is_null()
        || one(
            &v["conclusion"],
            &[
                "success",
                "failure",
                "neutral",
                "cancelled",
                "skipped",
                "timed_out",
                "action_required",
                "stale",
                "startup_failure",
            ],
        ))
        && (v["status"] == "completed" || v["conclusion"].is_null())
}
fn pull(v: &Value) -> bool {
    keys(
        v,
        &[
            "id",
            "number",
            "title",
            "state",
            "draft",
            "headSha",
            "headBranch",
            "headRepository",
            "baseSha",
            "baseBranch",
            "updatedAt",
        ],
    ) && number(&v["id"])
        && number(&v["number"])
        && text(&v["title"], 512)
        && one(&v["state"], &["open", "closed"])
        && v["draft"].is_boolean()
        && sha(&v["headSha"])
        && text(&v["headBranch"], 200)
        && (v["headRepository"].is_null() || v["headRepository"].as_str().is_some_and(coordinate))
        && sha(&v["baseSha"])
        && text(&v["baseBranch"], 200)
        && time(&v["updatedAt"])
}
fn run(v: &Value) -> bool {
    keys(
        v,
        &[
            "id",
            "attempt",
            "name",
            "status",
            "conclusion",
            "headSha",
            "headBranch",
            "headRepository",
            "event",
            "createdAt",
            "updatedAt",
        ],
    ) && number(&v["id"])
        && v["attempt"]
            .as_u64()
            .is_some_and(|n| (1..=1000).contains(&n))
        && text(&v["name"], 512)
        && status(v)
        && sha(&v["headSha"])
        && (v["headBranch"].is_null() || text(&v["headBranch"], 200))
        && (v["headRepository"].is_null() || v["headRepository"].as_str().is_some_and(coordinate))
        && text(&v["event"], 64)
        && time(&v["createdAt"])
        && time(&v["updatedAt"])
}
fn file(v: &Value) -> bool {
    keys(v, &["path", "change", "additions", "deletions"])
        && text(&v["path"], 1024)
        && one(
            &v["change"],
            &[
                "added",
                "removed",
                "modified",
                "renamed",
                "copied",
                "changed",
                "unchanged",
            ],
        )
        && count(&v["additions"])
        && count(&v["deletions"])
}
fn review(v: &Value) -> bool {
    keys(v, &["id", "reviewer", "state", "commitSha", "submittedAt"])
        && number(&v["id"])
        && (v["reviewer"].is_null()
            || v["reviewer"]
                .as_str()
                .is_some_and(crate::github_repository_create_protocol::login))
        && one(
            &v["state"],
            &[
                "APPROVED",
                "CHANGES_REQUESTED",
                "COMMENTED",
                "DISMISSED",
                "PENDING",
            ],
        )
        && (v["commitSha"].is_null() || sha(&v["commitSha"]))
        && (v["submittedAt"].is_null() || time(&v["submittedAt"]))
}
fn commit_status(v: &Value) -> bool {
    keys(v, &["id", "name", "state", "updatedAt"])
        && number(&v["id"])
        && text(&v["name"], 512)
        && one(&v["state"], &["error", "failure", "pending", "success"])
        && time(&v["updatedAt"])
}
fn job(v: &Value) -> bool {
    keys(v, &["id", "name", "status", "conclusion"])
        && number(&v["id"])
        && text(&v["name"], 512)
        && status(v)
}
fn section(v: &Value, check: fn(&Value) -> bool, identity: &str) -> bool {
    if !keys(v, &["state", "reason", "coverage", "total", "rows"]) {
        return false;
    }
    let Some(rows) = v["rows"].as_array() else {
        return false;
    };
    if rows.len() > 30 {
        return false;
    }
    if v["state"] == "unavailable" {
        return one(&v["reason"], &["forbidden", "not-found-or-inaccessible"])
            && v["coverage"] == "unknown"
            && v["total"].is_null()
            && rows.is_empty();
    }
    let mut ids = std::collections::BTreeSet::new();
    v["state"] == "read"
        && v["reason"] == "none"
        && (v["total"].is_null()
            || count(&v["total"]) && v["total"].as_u64().is_some_and(|n| n >= rows.len() as u64))
        && (if v["total"].as_u64() == Some(rows.len() as u64) {
            v["coverage"] == "complete"
        } else {
            v["coverage"] == "windowed"
        })
        && rows
            .iter()
            .all(|r| check(r) && ids.insert(r[identity].as_str()))
}
pub(crate) fn data_valid(v: &Value, r: &Request) -> bool {
    match &r.selection {
        Selection::Overview { branch } => {
            keys(v, &["kind", "branchHead", "pullRequests", "workflowRuns"])
                && v["kind"] == "overview"
                && (if branch.is_some() {
                    sha(&v["branchHead"])
                } else {
                    v["branchHead"].is_null()
                })
                && section(&v["pullRequests"], pull, "id")
                && section(&v["workflowRuns"], run, "id")
                && branch.as_ref().is_none_or(|b| {
                    v["pullRequests"]["rows"].as_array().is_some_and(|rows| {
                        rows.iter().all(|p| {
                            p["headBranch"].as_str() == Some(b)
                                && p["headRepository"]
                                    .as_str()
                                    .is_some_and(|n| n.eq_ignore_ascii_case(&r.target.repository))
                        })
                    }) && v["workflowRuns"]["rows"].as_array().is_some_and(|rows| {
                        rows.iter().all(|row| {
                            row["headBranch"].as_str() == Some(b)
                                && row["headRepository"]
                                    .as_str()
                                    .is_some_and(|n| n.eq_ignore_ascii_case(&r.target.repository))
                        })
                    })
                })
        }
        Selection::PullRequest { number } => {
            keys(
                v,
                &[
                    "kind",
                    "pullRequest",
                    "changedFiles",
                    "reviews",
                    "commitStatuses",
                    "checkRuns",
                    "headChecked",
                ],
            ) && v["kind"] == "pull-request"
                && v["headChecked"] == true
                && pull(&v["pullRequest"])
                && v["pullRequest"]["number"].as_str() == Some(number)
                && section(&v["changedFiles"], file, "path")
                && section(&v["reviews"], review, "id")
                && section(&v["commitStatuses"], commit_status, "id")
                && section(&v["checkRuns"], job, "id")
        }
        Selection::WorkflowRun { run_id, attempt } => {
            keys(v, &["kind", "run", "jobs", "attemptChecked"])
                && v["kind"] == "workflow-run"
                && v["attemptChecked"] == true
                && run(&v["run"])
                && v["run"]["id"].as_str() == Some(run_id)
                && v["run"]["attempt"].as_u64() == Some(u64::from(*attempt))
                && section(&v["jobs"], job, "id")
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResultData {
    pub(crate) schema_version: u32,
    pub(crate) target: Target,
    pub(crate) selection: Selection,
    pub(crate) observed_at: String,
    pub(crate) reason: Reason,
    #[serde(deserialize_with = "nullable")]
    pub(crate) data: Option<Value>,
    pub(crate) control: GitHubReadControl,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reply {
    pub(crate) protocol: String,
    pub(crate) id: String,
    pub(crate) result: ResultData,
}
impl Reply {
    pub(crate) fn heap(&self) -> Option<usize> {
        strings(&[&self.id, &self.protocol, &self.result.observed_at])?
            .checked_add(self.result.target.heap()?)?
            .checked_add(self.result.selection.heap())?
            .checked_add(self.result.data.as_ref().map_or(Some(0), value_heap)?)
    }
}
pub(crate) fn decode_reply(id: &str, raw: &[u8], r: &Request) -> Result<Reply, BridgeError> {
    let v: Reply = serde_json::from_value(frame(raw, RESPONSE_LIMIT, 8192)?)
        .map_err(|_| BridgeError::protocol())?;
    let d = &v.result;
    if v.protocol != PROTOCOL
        || v.id != id
        || !r.valid()
        || d.schema_version != 1
        || d.target != r.target
        || d.selection != r.selection
        || !utc(&d.observed_at)
        || !d.reason.core()
        || !d.control.valid()
        || (d.reason == Reason::None) != d.data.is_some()
        || d.data.as_ref().is_some_and(|v| !data_valid(v, r))
    {
        return Err(BridgeError::protocol());
    }
    Ok(v)
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Observation {
    pub(crate) target: Target,
    pub(crate) selection: Selection,
    pub(crate) observed_at: String,
    pub(crate) data: Value,
}
impl Observation {
    fn heap(&self) -> Option<usize> {
        self.target
            .heap()?
            .checked_add(self.selection.heap())?
            .checked_add(self.observed_at.capacity())?
            .checked_add(value_heap(&self.data)?)
    }
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
    pub(crate) target: Target,
    pub(crate) selection: Selection,
    pub(crate) phase: Phase,
    pub(crate) reason: Reason,
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
    pub(crate) result: Option<Observation>,
}
impl Status {
    pub(crate) fn fits(&self) -> bool {
        canonical(self).is_ok_and(|v| v.len() <= RESPONSE_LIMIT)
    }
    pub(crate) fn heap(&self) -> Option<usize> {
        let mut n = self.session_id.as_ref().map_or(0, String::capacity);
        if let Some(o) = &self.operation {
            n = n
                .checked_add(strings(&[&o.id, &o.project_id])?)?
                .checked_add(o.target.heap()?)?
                .checked_add(o.selection.heap())?;
        }
        n.checked_add(self.result.as_ref().map_or(Some(0), Observation::heap)?)
    }
}
fn strings(v: &[&String]) -> Option<usize> {
    v.iter()
        .try_fold(0usize, |n, s| n.checked_add(s.capacity()))
}
// Conservative BTreeMap allocation charge plus actual owned string/Vec capacity.
// Bounds are checked before decoding; no serialized length as a heap receipt.
fn value_heap(v: &Value) -> Option<usize> {
    match v {
        Value::String(s) => Some(s.capacity()),
        Value::Array(rows) => rows.iter().try_fold(
            rows.capacity().checked_mul(std::mem::size_of::<Value>())?,
            |n, v| n.checked_add(value_heap(v)?),
        ),
        Value::Object(rows) => rows.iter().try_fold(
            rows.len().checked_mul(256 + std::mem::size_of::<Value>())?,
            |n, (k, v)| n.checked_add(k.capacity())?.checked_add(value_heap(v)?),
        ),
        _ => Some(0),
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReadArgs {
    pub(crate) session_id: String,
    pub(crate) project_id: String,
    pub(crate) expected_revision: u32,
    pub(crate) expected_connection_revision: u32,
    pub(crate) selection: Selection,
}
pub(crate) enum Command {
    Status,
    Read(ReadArgs),
    Cancel(crate::github_setup_protocol::CancelArgs),
}
pub(crate) fn raw_input(bytes: &[u8]) -> Result<Value, BridgeError> {
    if bytes.is_empty() || bytes.len() > 1024 {
        return Err(BridgeError::invalid());
    }
    let v = strict_json(bytes).map_err(|_| BridgeError::invalid())?;
    if !v.is_object() || !bounds(&v, 1024, 32, 4) {
        return Err(BridgeError::invalid());
    }
    Ok(v)
}
pub(crate) fn decode_command(name: &str, v: &Value) -> Result<Command, BridgeError> {
    if !v.is_object() || !bounds(v, 1024, 32, 4) {
        return Err(BridgeError::invalid());
    }
    match name {
        "github_activity_status" if v.as_object().is_some_and(|o| o.is_empty()) => {
            Ok(Command::Status)
        }
        "github_activity_read" => {
            let a: ReadArgs =
                serde_json::from_value(v.clone()).map_err(|_| BridgeError::invalid())?;
            if !valid_id(&a.session_id)
                || !valid_id(&a.project_id)
                || !(1..=LAST_REVISION).contains(&a.expected_revision)
                || !(1..=LAST_REVISION).contains(&a.expected_connection_revision)
                || !a.selection.valid()
            {
                return Err(BridgeError::invalid());
            }
            Ok(Command::Read(a))
        }
        "github_activity_cancel" => {
            let a: crate::github_setup_protocol::CancelArgs =
                serde_json::from_value(v.clone()).map_err(|_| BridgeError::invalid())?;
            if !valid_id(&a.operation_id) {
                return Err(BridgeError::invalid());
            }
            Ok(Command::Cancel(a))
        }
        _ => Err(BridgeError::invalid()),
    }
}

#[cfg(test)]
mod activity_data_tests {
    use super::*;
    fn request() -> Request {
        Request {
            target: Target {
                project_binding: "f".repeat(64),
                repository: "example/application".into(),
                account_id: "7".into(),
                repository_id: "9".into(),
            },
            selection: Selection::Overview { branch: None },
        }
    }
    fn section() -> Value {
        serde_json::json!({"state":"read","reason":"none","coverage":"complete","total":0,"rows":[]})
    }
    fn reply(request: &Request) -> Value {
        serde_json::json!({"protocol":PROTOCOL,"id":"activity-a","result":{"schemaVersion":1,"target":request.target,
            "selection":request.selection,"observedAt":"2026-10-20T12:00:00Z","reason":"none",
            "data":{"kind":"overview","branchHead":null,"pullRequests":section(),"workflowRuns":section()},
            "control":{"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}}})
    }
    fn line(v: &Value) -> Vec<u8> {
        let mut b = canonical(v).unwrap();
        b.push(b'\n');
        b
    }

    #[test]
    fn activity_raw_commands_are_closed_data_only() {
        let v = serde_json::json!({"sessionId":"session-a","projectId":"project-a","expectedRevision":1,
            "expectedConnectionRevision":2,"selection":{"kind":"overview","branch":null}});
        assert!(decode_command(
            "github_activity_read",
            &raw_input(&canonical(&v).unwrap()).unwrap()
        )
        .is_ok());
        for (key, value) in [
            ("token", Value::String("inert".into())),
            ("url", Value::String("https://invalid.example".into())),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(decode_command("github_activity_read", &bad).is_err());
        }
        assert!(raw_input(br#"{"operationId":"a","operation\u0049d":"a"}"#).is_err());
        assert!(raw_input(&vec![b' '; 1025]).is_err());
        let mut bad = v.clone();
        bad["selection"] = serde_json::json!({"kind":"overview"});
        assert!(decode_command("github_activity_read", &bad).is_err());
        assert!(decode_command("github_activity_rerun", &v).is_err());
    }

    #[test]
    fn activity_ready_and_go_bind_original_request_not_public_finality() {
        let r = request();
        let b = encode_initial("activity-a", &r).unwrap();
        let digest = crate::github_preflight_protocol::request_digest(&b);
        let ready = line(
            &serde_json::json!({"protocol":PROTOCOL,"id":"activity-a","ready":{"requestSha256":digest}}),
        );
        assert!(decode_ready(&ready, "activity-a", &digest).is_ok());
        assert!(decode_ready(&ready, "activity-b", &digest).is_err());
        let bytes = encode_go("activity-a", &digest, "synthetic-fixture-only", &r).unwrap();
        assert!(bytes.len() <= GO_LIMIT);
        let value = frame(&bytes, GO_LIMIT, 32).unwrap();
        assert!(keys(&value["go"], &["requestSha256", "token"]));
        assert!(encode_go("activity-a", &digest, "bad\nvalue", &r).is_err());
    }

    #[test]
    fn activity_reply_has_exact_selection_and_no_approval_or_body_fields() {
        let r = request();
        let v = reply(&r);
        assert!(decode_reply("activity-a", &line(&v), &r).is_ok());
        let mut foreign = v.clone();
        foreign["result"]["target"]["repositoryId"] = Value::String("10".into());
        assert!(decode_reply("activity-a", &line(&foreign), &r).is_err());
        for field in ["approved", "body", "logs", "token"] {
            let mut bad = v.clone();
            bad["result"]["data"][field] = Value::Bool(true);
            assert!(decode_reply("activity-a", &line(&bad), &r).is_err());
        }
        let mut partial = v.clone();
        partial["result"]["data"]["workflowRuns"]["total"] = Value::from(1);
        assert!(decode_reply("activity-a", &line(&partial), &r).is_err());
        partial["result"]["data"]["workflowRuns"]["coverage"] = Value::String("windowed".into());
        assert!(decode_reply("activity-a", &line(&partial), &r).is_ok());
        let mut unknown = v.clone();
        unknown["result"]["reason"] = Value::String("cleanup-unknown".into());
        // A child DATA result cannot claim the original native owner's finality.
        assert!(decode_reply("activity-a", &line(&unknown), &r).is_err());
    }
}
