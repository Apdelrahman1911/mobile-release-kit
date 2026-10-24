//! Closed GitRead DATA. Native source snapshots are never renderer authority.
//! The public result omits paths to tools/roots, raw errors, commit identities,
//! messages and credentials. A decoded child terminal is not native finality.
use crate::{
    error::BridgeError,
    protocol::{strict_json, valid_id},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(crate) const PROTOCOL: &str = "mrk-git-read/1";
pub(crate) const REQUEST_LIMIT: usize = 96 * 1024;
pub(crate) const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const READY_LIMIT: usize = 512;
pub(crate) const WORK_SECONDS: u64 = 45;
pub(crate) const HARD_SECONDS: u64 = 55;
pub(crate) const TOOL_PATH: &str = "/Library/Developer/CommandLineTools/usr/bin/git";
pub(crate) const TOOL_LIMIT: u64 = 128 * 1024 * 1024;
pub(crate) const INDEX_LIMIT: u64 = 16 * 1024 * 1024;
// One request, bounded two-frame output, decoded/serialized overlap, fixed
// source hash scratch and finite control cells. Runtime code has its own debit.
pub(crate) const DATA_BACKING: usize = 11 * 1024 * 1024;
// Closed Observe is <=512 paths +4096 bounded remote names; Diff is256KiB,
// History25 metadata rows. Includes decoded Value/map/key allocation slack.
pub(crate) const RESULT_BACKING: usize = 2 * 1024 * 1024;

fn need(value: bool) -> Result<(), BridgeError> {
    if value {
        Ok(())
    } else {
        Err(BridgeError::protocol())
    }
}
fn keys(value: &Value, names: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|v| v.len() == names.len() && names.iter().all(|name| v.contains_key(*name)))
}
pub(crate) fn text(value: &str, limit: usize, multiline: bool) -> bool {
    value.len() <= limit
        && !value
            .chars()
            .any(|c| c == '\u{7f}' || (c < ' ' && !(multiline && matches!(c, '\n' | '\r' | '\t'))))
}
pub(crate) fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn relative(value: &str) -> bool {
    !value.is_empty()
        && text(value, 1024, false)
        && !value.contains('\\')
        && value.split('/').count() <= 32
        && value
            .split('/')
            .all(|v| !v.is_empty() && v.len() <= 255 && !matches!(v, "." | ".." | ".git"))
}
fn reference(value: &str) -> bool {
    value.starts_with("refs/")
        && text(value, 1024, false)
        && !value.contains("..")
        && !value.contains("@{")
        && !value.chars().any(|c| c <= ' ' || "~^:?*[\\".contains(c))
        && value
            .split('/')
            .all(|v| !v.is_empty() && !v.starts_with('.') && !v.ends_with('.') && !v.ends_with(".lock"))
}
pub(crate) fn branch(value: &str) -> bool {
    value.starts_with("refs/heads/") && reference(value)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    Observe,
    Diff,
    History,
    Branches,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind: Kind,
    pub(crate) expected_revision: Option<String>,
    pub(crate) paths: Vec<String>,
    pub(crate) staged: bool,
}
impl Action {
    pub(crate) fn valid(&self) -> bool {
        match self.kind {
            Kind::Observe => self.expected_revision.is_none() && self.paths.is_empty() && !self.staged,
            Kind::History|Kind::Branches => self.expected_revision.as_deref().is_some_and(digest) && self.paths.is_empty() && !self.staged,
            Kind::Diff => {
                self.expected_revision.as_deref().is_some_and(digest)
                    && !self.paths.is_empty()
                    && self.paths.len() <= 64
                    && self.paths.iter().all(|p| relative(p))
                    && self.paths.windows(2).all(|p| p[0] < p[1])
            }
        }
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Start {
    pub(crate) project_id: String,
    pub(crate) expected_document_revision: u32,
    pub(crate) action: Action,
}
pub(crate) enum Command {
    Start(Start),
    Status,
    Cancel(String),
}
pub(crate) fn decode_command(name: &str, raw: &[u8]) -> Result<Command, BridgeError> {
    let limit = if name == "git_read_start" { REQUEST_LIMIT } else { 1024 };
    need(raw.len().saturating_add(name.len()).saturating_add(32) <= limit)?;
    let body = strict_json(raw)?;
    match name {
        "git_read_status" if keys(&body, &[]) => Ok(Command::Status),
        "git_read_cancel" if keys(&body, &["operationId"]) => {
            let id = body["operationId"]
                .as_str()
                .filter(|v| valid_id(v))
                .ok_or_else(BridgeError::invalid)?;
            Ok(Command::Cancel(id.into()))
        }
        "git_read_start"
            if keys(&body, &["projectId", "expectedDocumentRevision", "action"])
                && keys(&body["action"], &["kind", "expectedRevision", "paths", "staged"]) =>
        {
            let id = body["projectId"]
                .as_str()
                .filter(|v| valid_id(v))
                .ok_or_else(BridgeError::invalid)?;
            let revision = body["expectedDocumentRevision"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .filter(|v| *v != 0 && *v != u32::MAX)
                .ok_or_else(BridgeError::invalid)?;
            let action: Action = serde_json::from_value(body["action"].clone()).map_err(|_| BridgeError::invalid())?;
            need(action.valid())?;
            Ok(Command::Start(Start {
                project_id: id.into(),
                expected_document_revision: revision,
                action,
            }))
        }
        _ => Err(BridgeError::invalid()),
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Context {
    pub(crate) project_id: String,
    pub(crate) generation: u32,
    pub(crate) revision: String,
}
pub(crate) type DirectoryIdentity = (u64, u64, u32, u32, u32);
pub(crate) type FileIdentity = (u64, u64, u32, u32, u32, u64, u64, i64, i64);
// These private DATA are produced only from the still-held SourceBook. No
// Deserialize or public constructor accepts a renderer's claimed snapshot.
#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) identity: FileIdentity,
    pub(crate) sha256: String,
}
#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct Directories {
    pub(crate) root: DirectoryIdentity,
    pub(crate) git: DirectoryIdentity,
    pub(crate) objects: DirectoryIdentity,
}
#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct Files {
    #[serde(rename = "HEAD")]
    pub(crate) head: Snapshot,
    pub(crate) config: Snapshot,
    pub(crate) index: Option<Snapshot>,
}
#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct Native {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) root: String,
    pub(crate) directories: Directories,
    pub(crate) tool: Snapshot,
    pub(crate) files: Files,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Clock {
    pub(crate) work_end_ns: u64,
    pub(crate) hard_end_ns: u64,
}
fn file_valid(s: &Snapshot, uid: u32, limit: u64, executable: bool) -> bool {
    let (dev, ino, mode, owner, _, links, bytes, _, _) = s.identity;
    dev != 0
        && ino != 0
        && mode & 0o170000 == 0o100000
        && owner == uid
        && links == 1
        && bytes <= limit
        && mode & 0o7022 == 0
        && (!executable || mode & 0o111 != 0 && bytes > 0)
        && digest(&s.sha256)
}
impl Native {
    pub(crate) fn valid(&self) -> bool {
        self.uid != 0
            && self.root.starts_with('/')
            && self.root.len() <= 4096
            && self.root[1..].split('/').count() <= 62
            && !self.root.contains('\\')
            && text(&self.root, 4096, false)
            && self.root[1..]
                .split('/')
                .all(|p| !p.is_empty() && p.len() <= 255 && !matches!(p, "." | ".." | ".git"))
            && [&self.directories.root, &self.directories.git, &self.directories.objects]
                .iter()
                .all(|d| d.0 > 0 && d.1 > 0 && d.2 & 0o170000 == 0o040000 && d.3 == self.uid && d.2 & 0o7022 == 0)
            && file_valid(&self.tool, 0, TOOL_LIMIT, true)
            && file_valid(&self.files.head, self.uid, 2048, false)
            && self.files.head.identity.6 != 0
            && file_valid(&self.files.config, self.uid, 65536, false)
            && self
                .files
                .index
                .as_ref()
                .is_none_or(|s| file_valid(s, self.uid, INDEX_LIMIT, false))
    }
}
pub(crate) struct Request {
    pub(crate) id: String,
    pub(crate) action: Action,
    pub(crate) context: Context,
    pub(crate) clock: Clock,
    bytes: Vec<u8>,
    pub(crate) digest: String,
}
impl Request {
    pub(crate) fn from_original(id: &str, action: &Action, context: &Context, native: &Native, clock: Clock) -> Result<Self, BridgeError> {
        need(
            valid_id(id)
                && action.valid()
                && valid_id(&context.project_id)
                && valid_id(&context.revision)
                && native.valid()
                && clock.work_end_ns > 0
                && clock.hard_end_ns <= i64::MAX as u64
                && clock.hard_end_ns.checked_sub(clock.work_end_ns) == Some(10_000_000_000),
        )?;
        let mut bytes =
            serde_json::to_vec(&json!({"protocol":PROTOCOL,"id":id,"action":action,"context":context,"native":native,"clock":clock}))
                .map_err(|_| BridgeError::protocol())?;
        bytes.push(b'\n');
        need(bytes.len() <= REQUEST_LIMIT)?;
        let digest = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            id: id.into(),
            action: action.clone(),
            context: context.clone(),
            clock,
            bytes,
            digest,
        })
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn go(&self) -> Vec<u8> {
        format!("MRK-GIT-READ-GO/1 {}\n", self.digest).into_bytes()
    }
    pub(crate) fn ready(&self, bytes: &[u8]) -> Result<(), BridgeError> {
        let row = frame(bytes, READY_LIMIT)?;
        need(
            keys(&row, &["protocol", "id", "digest"])
                && row["protocol"] == PROTOCOL
                && row["id"] == self.id
                && row["digest"] == self.digest,
        )
    }
    pub(crate) fn terminal(&self, bytes: &[u8]) -> Result<Terminal, BridgeError> {
        let row = frame(bytes, RESPONSE_LIMIT)?;
        need(
            keys(
                &row,
                &[
                    "protocol",
                    "id",
                    "digest",
                    "action",
                    "status",
                    "reason",
                    "result",
                    "firstFailureNs",
                    "cleanupEndNs",
                ],
            ) && row["protocol"] == PROTOCOL
                && row["id"] == self.id
                && row["digest"] == self.digest,
        )?;
        let terminal: Terminal = serde_json::from_value(row).map_err(|_| BridgeError::protocol())?;
        need(terminal.action == self.action.kind && terminal.cleanup_end_ns > 0 && terminal.cleanup_end_ns <= self.clock.hard_end_ns)?;
        if let Some(first) = terminal.first_failure_ns {
            need(first > 0 && first <= terminal.cleanup_end_ns && terminal.cleanup_end_ns - first <= 10_000_000_000)?;
        }
        if terminal.status == Outcome::Ok {
            need(terminal.reason.is_none() && terminal.first_failure_ns.is_none() && terminal.cleanup_end_ns == self.clock.hard_end_ns)?;
            validate_result(&self.action, &terminal.result)?;
        } else {
            need(
                terminal.reason.as_deref().is_some_and(reason)
                    && terminal.result.is_null()
                    && (terminal.status == Outcome::CleanupUnknown || terminal.first_failure_ns.is_some()),
            )?;
        }
        Ok(terminal)
    }
}
fn frame(bytes: &[u8], limit: usize) -> Result<Value, BridgeError> {
    need(!bytes.is_empty() && bytes.len() <= limit && bytes.last() == Some(&b'\n') && bytes.iter().filter(|b| **b == b'\n').count() == 1)?;
    strict_json(bytes)
}

pub(crate) const REASONS: &[&str] = &[
    "invalid-input",
    "not-repository",
    "unsupported-repository",
    "unsupported-path",
    "unsupported-filter",
    "required-hooks",
    "required-signing",
    "conflicts",
    "nothing-staged",
    "sensitive-content",
    "stale-observation",
    "locked",
    "authorization",
    "deadline",
    "limit",
    "command-failed",
    "response-invalid",
    "recovery-required",
    "unknown",
    "already-used",
    "operation-in-progress",
];
pub(crate) fn reason(value: &str) -> bool {
    REASONS.contains(&value)
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome {
    Ok,
    Refused,
    Cancelled,
    TimedOut,
    CleanupUnknown,
}
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Terminal {
    protocol: String,
    id: String,
    digest: String,
    pub(crate) action: Kind,
    pub(crate) status: Outcome,
    pub(crate) reason: Option<String>,
    pub(crate) result: Value,
    pub(crate) first_failure_ns: Option<u64>,
    pub(crate) cleanup_end_ns: u64,
}
impl Terminal {
    // Necessary child-side declaration ONLY. The original owner separately
    // requires child wait, EOF, each close and every actual task/native join.
    pub(crate) fn child_declared_settled(&self) -> bool {
        self.status != Outcome::CleanupUnknown && self.reason.as_deref() != Some("unknown")
    }
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Starting,
    Running,
    Stopping,
    Settled,
    CleanupUnknown,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Projection {
    pub(crate) operation_id: String,
    pub(crate) context: Context,
    pub(crate) action: Action,
    pub(crate) phase: Phase,
    pub(crate) outcome: Option<Outcome>,
    pub(crate) reason: Option<String>,
    pub(crate) result: Value,
    // Original-error diagnostic DATA only. Reconcile/Clone retains it without
    // another owner query; neither public read status nor policy consumes it.
    #[serde(skip)]
    pub(crate) failure_provenance: Option<crate::error::GitReadFailureProvenance>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub(crate) schema_version: u8,
    pub(crate) document_revision: u32,
    pub(crate) available: bool,
    pub(crate) operation: Option<Projection>,
}

// START alone has an explicit original-admission acknowledgement. A refusal
// is minted before roster insertion, never from a lost/failed child or transport.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Admission {
    Started,
    Refused,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum StartRefusal {
    InvalidInput,
    StaleObservation,
    Unavailable,
    Busy,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartResult {
    pub(crate) schema_version: u8,
    pub(crate) admission: Admission,
    pub(crate) request: Start,
    pub(crate) status: Status,
    pub(crate) reason: Option<StartRefusal>,
}

fn nullable_text(v: &Value, check: fn(&str) -> bool) -> bool {
    v.is_null() || v.as_str().is_some_and(check)
}
fn string_array(v: &Value, max: usize, check: impl Fn(&str) -> bool) -> bool {
    v.as_array().is_some_and(|rows| {
        rows.len() <= max
            && rows.iter().all(|v| v.as_str().is_some_and(&check))
            && rows.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>().len() == rows.len()
    })
}
pub(crate) fn observation(v: &Value) -> bool {
    if !keys(
        v,
        &[
            "revision",
            "head",
            "branch",
            "unborn",
            "detached",
            "changes",
            "remotes",
            "restrictions",
        ],
    ) || !v["revision"].as_str().is_some_and(digest)
        || !nullable_text(&v["head"], oid)
        || !nullable_text(&v["branch"], branch)
        || v["unborn"].as_bool() != Some(v["head"].is_null())
        || v["detached"].as_bool() != Some(v["branch"].is_null())
        || v["head"].is_null() && v["branch"].is_null()
        || !string_array(&v["remotes"], 4096, |s| !s.is_empty() && text(s, 128, false))
        || !string_array(&v["restrictions"], REASONS.len(), reason)
    {
        return false;
    }
    v["changes"].as_array().is_some_and(|rows| {
        let mut paths = BTreeSet::new();
        rows.len() <= 512
            && rows.iter().all(|r| {
                if !keys(r, &["path", "index", "worktree", "kind", "conflict"]) {
                    return false;
                }
                let (Some(path), Some(index), Some(worktree), Some(kind)) =
                    (r["path"].as_str(), r["index"].as_str(), r["worktree"].as_str(), r["kind"].as_str())
                else {
                    return false;
                };
                relative(path)
                    && paths.insert(path)
                    && index.len() == 1
                    && worktree.len() == 1
                    && " MTADRCU?!".contains(index)
                    && " MTADRCU?!".contains(worktree)
                    && ["absent", "file", "symlink", "directory", "other", "submodule"].contains(&kind)
                    && r["conflict"].as_bool()
                        == Some(["DD", "AU", "UD", "UA", "DU", "AA", "UU"].contains(&format!("{index}{worktree}").as_str()))
            })
    })
}
fn tracking(v: &Value) -> bool {
    if !keys(v, &["state", "remote", "mergeRef", "localRef", "head", "ahead", "behind"])
        || !nullable_text(&v["remote"], |s| !s.is_empty() && text(s, 128, false))
        || !nullable_text(&v["mergeRef"], reference)
        || !nullable_text(&v["localRef"], reference)
        || !nullable_text(&v["head"], oid)
    {
        return false;
    }
    let pair = !v["remote"].is_null() && !v["mergeRef"].is_null();
    let empty = ["remote", "mergeRef", "localRef", "head", "ahead", "behind"]
        .iter()
        .all(|k| v[*k].is_null());
    match v["state"].as_str() {
        Some("detached" | "not-configured") => empty,
        Some("unsupported" | "unborn") => (empty || pair) && ["localRef", "head", "ahead", "behind"].iter().all(|k| v[*k].is_null()),
        Some("gone") => pair && !v["localRef"].is_null() && ["head", "ahead", "behind"].iter().all(|k| v[*k].is_null()),
        Some("shallow" | "limit") => {
            pair && !v["localRef"].is_null() && !v["head"].is_null() && v["ahead"].is_null() && v["behind"].is_null()
        }
        Some("complete") => {
            pair && !v["localRef"].is_null()
                && !v["head"].is_null()
                && v["ahead"]
                    .as_u64()
                    .zip(v["behind"].as_u64())
                    .is_some_and(|(a, b)| a <= 10000 && b <= 10000 && a + b <= 10000)
        }
        _ => false,
    }
}
pub(crate) fn validate_result(action: &Action, v: &Value) -> Result<(), BridgeError> {
    match action.kind {
        Kind::Observe => need(
            keys(v, &["observation", "referenceRevision", "tracking", "basis"])
                && v["basis"] == "local-refs-no-fetch"
                && v["referenceRevision"].as_str().is_some_and(digest)
                && observation(&v["observation"])
                && tracking(&v["tracking"])
                && (v["tracking"]["state"] == "detached") == (v["observation"]["detached"] == true)
                && (v["observation"]["unborn"] != true || matches!(v["tracking"]["state"].as_str(), Some("unborn" | "unsupported")))
                && (v["tracking"]["state"] != "unborn" || v["observation"]["unborn"] == true)
                && (v["tracking"]["head"].is_null()
                    || v["tracking"]["head"].as_str().map(str::len) == v["observation"]["head"].as_str().map(str::len)),
        ),
        Kind::Diff => {
            need(
                keys(v, &["revision", "staged", "paths", "text", "withheld"])
                    && v["revision"].as_str() == action.expected_revision.as_deref()
                    && v["staged"].as_bool() == Some(action.staged)
                    && v["paths"] == json!(action.paths),
            )?;
            need(if v["withheld"].is_null() {
                v["text"].as_str().is_some_and(|s| text(s, 256 * 1024, true))
            } else {
                v["text"].is_null()
                    && v["withheld"]
                        .as_str()
                        .is_some_and(|s| ["sensitive-content", "untracked", "non-text"].contains(&s))
            })
        }
        Kind::Branches => crate::git_branch_protocol::validate_list(action.expected_revision.as_deref(),v),
        Kind::History => {
            need(
                keys(
                    v,
                    &[
                        "revision",
                        "referenceRevision",
                        "head",
                        "commits",
                        "hasMore",
                        "shallow",
                        "withheld",
                        "basis",
                    ],
                ) && v["revision"].as_str() == action.expected_revision.as_deref()
                    && v["referenceRevision"].as_str().is_some_and(digest)
                    && nullable_text(&v["head"], oid)
                    && v["hasMore"].is_boolean()
                    && v["shallow"].is_boolean()
                    && v["basis"] == "local-refs-no-fetch"
                    && v["withheld"] == json!(["message", "author", "email", "signature"]),
            )?;
            let rows = v["commits"].as_array().ok_or_else(BridgeError::protocol)?;
            need(
                rows.len() <= 25
                    && (rows.is_empty() == v["head"].is_null())
                    && (rows.len() == 25 || v["hasMore"] == false)
                    && (rows.is_empty() || rows[0]["oid"] == v["head"]),
            )?;
            let mut seen = BTreeSet::new();
            for row in rows {
                need(keys(row, &["oid", "parents", "committedAt"]))?;
                let value = row["oid"].as_str().ok_or_else(BridgeError::protocol)?;
                need(
                    oid(value)
                        && seen.insert(value)
                        && Some(value.len()) == v["head"].as_str().map(str::len)
                        && string_array(&row["parents"], 16, |p| oid(p) && p.len() == value.len() && p != value)
                        && row["committedAt"].as_u64().is_some_and(|v| v <= 9_007_199_254_740_991),
                )?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn start() -> Value {
        json!({"projectId":"project-1","expectedDocumentRevision":2,"action":{"kind":"observe","expectedRevision":null,"paths":[],"staged":false}})
    }
    #[test]
    fn raw_closed_read_commands_do_not_admit_paths_tools_writes_or_duplicate_keys() {
        assert!(matches!(
            decode_command("git_read_start", &serde_json::to_vec(&start()).unwrap()),
            Ok(Command::Start(_))
        ));
        for extra in ["root", "tool", "environment", "token", "force", "native"] {
            let mut v = start();
            v[extra] = json!("untrusted");
            assert!(decode_command("git_read_start", &serde_json::to_vec(&v).unwrap()).is_err());
        }
        for kind in ["stage", "commit", "fetch", "push", "reconcile"] {
            let mut v = start();
            v["action"]["kind"] = json!(kind);
            assert!(decode_command("git_read_start", &serde_json::to_vec(&v).unwrap()).is_err());
        }
        assert!(decode_command("git_read_status", br#"{"operationId":"a","operationId":"b"}"#).is_err());
        assert!(decode_command("git_read_start", &vec![b' '; REQUEST_LIMIT]).is_err());
    }
    #[test]
    fn exact_read_action_scope_and_sorted_selected_paths() {
        let mut a = Action {
            kind: Kind::Diff,
            expected_revision: Some("a".repeat(64)),
            paths: vec!["one.txt".into()],
            staged: false,
        };
        assert!(a.valid());
        for path in ["../one", "/one", ".git/config", "one\\two", "a//b"] {
            a.paths = vec![path.into()];
            assert!(!a.valid());
        }
        a.paths = vec!["b".into(), "a".into()];
        assert!(!a.valid());
        a.paths = vec!["a".into(), "a".into()];
        assert!(!a.valid());
        a.paths.clear();
        a.kind = Kind::History;
        assert!(a.valid());
        a.staged = true;
        assert!(!a.valid());
        let mut v = start();
        v["action"].as_object_mut().unwrap().remove("expectedRevision");
        assert!(decode_command("git_read_start", &serde_json::to_vec(&v).unwrap()).is_err());
    }
    #[test]
    fn history_never_accepts_messages_or_claims_remote_freshness() {
        let a = Action {
            kind: Kind::History,
            expected_revision: Some("a".repeat(64)),
            paths: vec![],
            staged: false,
        };
        let mut v = json!({"revision":"a".repeat(64),"referenceRevision":"b".repeat(64),"head":"c".repeat(40),"commits":[{"oid":"c".repeat(40),"parents":[],"committedAt":1}],"hasMore":false,"shallow":false,"withheld":["message","author","email","signature"],"basis":"local-refs-no-fetch"});
        assert!(validate_result(&a, &v).is_ok());
        v["commits"][0]["message"] = json!("not displayed");
        assert!(validate_result(&a, &v).is_err());
        v["commits"][0].as_object_mut().unwrap().remove("message");
        v["basis"] = json!("remote-current");
        assert!(validate_result(&a, &v).is_err());
    }
}
