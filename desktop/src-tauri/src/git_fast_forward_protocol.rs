//! Closed cached-upstream FF DATA; never a source, ACK, or execution grant.
use crate::{
    error::BridgeError, git_local_protocol as local, git_read_protocol as read,
    git_switch_protocol as shared,
};
use serde::{Deserialize, Serialize};
pub(crate) use shared::{File, Log, NamedSnapshot, TargetLock};
pub(crate) use shared::{FILE_LIMIT, INDEX_LIMIT, LOG_LIMIT, MAX_BYTES, MAX_FILES};
pub(crate) const MESSAGE: &str = "MRK: fast-forward to reviewed cached tracking commit";
pub(crate) const REVIEW_KEYS: &[&str] = &[
    "action",
    "targetRef",
    "targetOid",
    "expectedRevision",
    "expectedReferenceRevision",
    "head",
    "branch",
    "expectedIndex",
    "paths",
    "trackedCount",
    "contentOnly",
    "basis",
    "files",
    "headLog",
    "branchLog",
    "reviewDigest",
];
pub(crate) const INTENT_KEYS: &[&str] = &[
    "action",
    "expectedRevision",
    "expectedReferenceRevision",
    "expectedRef",
    "expectedHead",
    "expectedIndex",
    "targetRef",
    "targetOid",
    "candidateIndex",
    "originalHead",
    "originalHeadLog",
    "originalBranchLog",
    "headLogEnabled",
    "branchLogEnabled",
    "footprint",
];
pub(crate) const RESULT_KEYS: &[&str] = shared::RESULT_KEYS;
fn need(value: bool) -> Result<(), BridgeError> {
    if value {
        Ok(())
    } else {
        Err(BridgeError::protocol())
    }
}
pub(crate) fn tracking_ref(value: &str) -> bool {
    value.strip_prefix("refs/remotes/").is_some_and(|s| {
        !s.is_empty()
            && s.contains('/')
            && s.rsplit('/').next() != Some("HEAD")
            && value.split('/').count() <= 32
            && read::branch(&format!("refs/heads/{s}"))
    })
}
pub(crate) fn reason(value: &str) -> bool {
    shared::reason(value)
        || matches!(
            value,
            "ff-target" | "ff-not-descendant" | "ff-layout" | "ff-log-limit"
        )
}
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Kind {
    #[serde(rename = "fast-forward")]
    FastForward,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind: Kind,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) target_ref: String,
    pub(crate) target_oid: String,
}
impl Action {
    pub(crate) fn valid(&self) -> bool {
        tracking_ref(&self.target_ref)
            && read::oid(&self.target_oid)
            && read::digest(&self.expected_revision)
            && read::digest(&self.expected_reference_revision)
    }
}
fn files(values: &[File], width: usize) -> bool {
    values.len() <= MAX_FILES
        && values.windows(2).all(|v| v[0].path < v[1].path)
        && values.iter().all(|v| {
            read::relative(&v.path)
                && matches!(v.mode.as_str(), "100644" | "100755")
                && read::oid(&v.source_oid)
                && read::oid(&v.target_oid)
                && v.source_oid.len() == width
                && v.target_oid.len() == width
                && v.source_oid != v.target_oid
                && read::digest(&v.source_sha256)
                && read::digest(&v.target_sha256)
                && v.target_size <= FILE_LIMIT
        })
        && values
            .iter()
            .try_fold(0u64, |n, v| n.checked_add(v.target_size))
            .is_some_and(|n| n <= MAX_BYTES)
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) action: Kind,
    pub(crate) target_ref: String,
    pub(crate) target_oid: String,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) head: String,
    pub(crate) branch: String,
    pub(crate) expected_index: String,
    pub(crate) paths: Vec<String>,
    pub(crate) tracked_count: u16,
    pub(crate) content_only: bool,
    pub(crate) basis: String,
    pub(crate) files: Vec<File>,
    pub(crate) head_log: Log,
    pub(crate) branch_log: Log,
    pub(crate) review_digest: String,
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        tracking_ref(&self.target_ref)
            && read::branch(&self.branch)
            && read::oid(&self.head)
            && read::oid(&self.target_oid)
            && self.head != self.target_oid
            && self.head.len() == self.target_oid.len()
            && [
                &self.expected_revision,
                &self.expected_reference_revision,
                &self.expected_index,
                &self.review_digest,
            ]
            .iter()
            .all(|v| read::digest(v))
            && self.content_only
            && self.basis == "local-refs-no-fetch"
            && self.tracked_count <= 256
            && self.files.len() <= usize::from(self.tracked_count)
            && files(&self.files, self.head.len())
            && self.paths.len() == self.files.len()
            && self
                .paths
                .iter()
                .zip(&self.files)
                .all(|(p, f)| p == &f.path)
            && self.head_log.valid()
            && self.branch_log.valid()
    }
    pub(crate) fn matches(&self, action: &Action) -> bool {
        self.valid()
            && action.valid()
            && self.target_ref == action.target_ref
            && self.target_oid == action.target_oid
            && self.expected_revision == action.expected_revision
            && self.expected_reference_revision == action.expected_reference_revision
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Intent {
    pub(crate) action: Kind,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) expected_ref: String,
    pub(crate) expected_head: String,
    pub(crate) expected_index: String,
    pub(crate) target_ref: String,
    pub(crate) target_oid: String,
    pub(crate) candidate_index: String,
    pub(crate) original_head: String,
    pub(crate) original_head_log: String,
    pub(crate) original_branch_log: String,
    pub(crate) head_log_enabled: bool,
    pub(crate) branch_log_enabled: bool,
    pub(crate) footprint: String,
}
impl Intent {
    pub(crate) fn valid(&self) -> bool {
        read::branch(&self.expected_ref)
            && tracking_ref(&self.target_ref)
            && read::oid(&self.expected_head)
            && read::oid(&self.target_oid)
            && self.expected_head != self.target_oid
            && self.expected_head.len() == self.target_oid.len()
            && [
                &self.expected_revision,
                &self.expected_reference_revision,
                &self.expected_index,
                &self.candidate_index,
                &self.original_head,
                &self.original_head_log,
                &self.original_branch_log,
                &self.footprint,
            ]
            .iter()
            .all(|s| read::digest(s))
            && self.original_head
                == shared::hash(format!("ref: {}\n", self.expected_ref).as_bytes())
    }
    pub(crate) fn matches(&self, r: &Review) -> bool {
        self.valid()
            && r.valid()
            && self.expected_revision == r.expected_revision
            && self.expected_reference_revision == r.expected_reference_revision
            && self.expected_ref == r.branch
            && self.expected_head == r.head
            && self.expected_index == r.expected_index
            && self.target_ref == r.target_ref
            && self.target_oid == r.target_oid
            && self.original_head_log == r.head_log.original_sha256
            && self.original_branch_log == r.branch_log.original_sha256
            && self.head_log_enabled == r.head_log.enabled
            && self.branch_log_enabled == r.branch_log.enabled
    }
}
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Sources {
    pub(crate) target_lock: TargetLock,
    pub(crate) head_log: Option<read::Snapshot>,
    pub(crate) branch_log: Option<read::Snapshot>,
    pub(crate) current_ref: NamedSnapshot,
    pub(crate) files: Vec<NamedSnapshot>,
}
fn file(s: &read::Snapshot, uid: u32, limit: u64) -> bool {
    let i = s.identity;
    i.0 > 0
        && i.1 > 0
        && i.2 & 0o170000 == 0o100000
        && i.2 & 0o7022 == 0
        && i.3 == uid
        && i.5 == 1
        && i.6 <= limit
        && read::digest(&s.sha256)
}
impl Sources {
    pub(crate) fn valid(&self, native: &read::Native, r: &Review) -> bool {
        let lock = &self.target_lock;
        native.valid()
            && r.valid()
            && native
                .files
                .index
                .as_ref()
                .is_some_and(|s| file(s, native.uid, INDEX_LIMIT) && s.sha256 == r.expected_index)
            && native.files.head.sha256 == shared::hash(format!("ref: {}\n", r.branch).as_bytes())
            && file(
                &read::Snapshot {
                    identity: lock.identity,
                    sha256: shared::hash(b""),
                },
                native.uid,
                0,
            )
            && lock.identity.2 == 0o100600
            && shared::parent_transition(lock.parent_before, lock.parent_locked)
            && [lock.parent_before, lock.parent_locked].iter().all(|i| {
                i.0 > 0
                    && i.1 > 0
                    && i.2 & 0o170000 == 0o040000
                    && i.2 & 0o7022 == 0
                    && i.3 == native.uid
                    && i.5 > 0
            })
            && self.current_ref.path == r.branch
            && file(&self.current_ref.snapshot, native.uid, 65)
            && self.current_ref.snapshot.sha256 == shared::hash(format!("{}\n", r.head).as_bytes())
            && [
                (&self.head_log, &r.head_log),
                (&self.branch_log, &r.branch_log),
            ]
            .iter()
            .all(|(s, l)| match s {
                Some(s) => {
                    l.original_kind == "file"
                        && file(s, native.uid, LOG_LIMIT)
                        && s.sha256 == l.original_sha256
                }
                None => l.original_kind == "absent",
            })
            && self.files.len() == r.files.len()
            && self.files.iter().zip(&r.files).all(|(s, f)| {
                s.path == f.path
                    && file(&s.snapshot, native.uid, FILE_LIMIT)
                    && s.snapshot.identity.2 == f.mode_bits()
                    && s.snapshot.sha256 == f.source_sha256
            })
            && self
                .files
                .iter()
                .try_fold(0u64, |n, v| n.checked_add(v.snapshot.identity.6))
                .is_some_and(|n| n <= MAX_BYTES)
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Journal {
    pub(crate) expected_reference_revision: String,
    pub(crate) target_ref: String,
    pub(crate) target_oid: String,
    pub(crate) files: Vec<File>,
    pub(crate) head_log: Log,
    pub(crate) branch_log: Log,
    pub(crate) footprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) final_state: Option<FinalData>,
}
impl Journal {
    pub(crate) fn preparing(r: &Review) -> Self {
        Self {
            expected_reference_revision: r.expected_reference_revision.clone(),
            target_ref: r.target_ref.clone(),
            target_oid: r.target_oid.clone(),
            files: r.files.clone(),
            head_log: r.head_log.clone(),
            branch_log: r.branch_log.clone(),
            footprint: None,
            final_state: None,
        }
    }
    pub(crate) fn valid(
        &self,
        head: Option<&str>,
        reference: Option<&str>,
        index: Option<&str>,
    ) -> bool {
        head.is_some_and(|h| {
            read::oid(h) && h.len() == self.target_oid.len() && h != self.target_oid
        }) && reference.is_some_and(read::branch)
            && tracking_ref(&self.target_ref)
            && read::oid(&self.target_oid)
            && read::digest(&self.expected_reference_revision)
            && files(&self.files, self.target_oid.len())
            && self.head_log.valid()
            && self.branch_log.valid()
            && match (&self.footprint, index) {
                (None, None) => self.final_state.is_none(),
                (Some(f), Some(i)) => {
                    read::digest(f)
                        && read::digest(i)
                        && self.final_state.as_ref().is_none_or(FinalData::valid)
                }
                _ => false,
            }
    }
    pub(crate) fn same_original(&self, old: &Self) -> bool {
        self.expected_reference_revision == old.expected_reference_revision
            && self.target_ref == old.target_ref
            && self.target_oid == old.target_oid
            && self.files == old.files
            && self.head_log == old.head_log
            && self.branch_log == old.branch_log
    }
    pub(crate) fn accepts(&self, i: &Intent) -> bool {
        self.footprint.is_none()
            && self.final_state.is_none()
            && i.valid()
            && self.expected_reference_revision == i.expected_reference_revision
            && self.target_ref == i.target_ref
            && self.target_oid == i.target_oid
            && self.head_log.enabled == i.head_log_enabled
            && self.branch_log.enabled == i.branch_log_enabled
            && self.head_log.original_sha256 == i.original_head_log
            && self.branch_log.original_sha256 == i.original_branch_log
    }
    pub(crate) fn candidate(&mut self, i: &Intent) {
        self.footprint = Some(i.footprint.clone());
    }
    pub(crate) fn intent(
        &self,
        revision: &str,
        reference: &str,
        head: &str,
        old_index: &str,
        index: &str,
    ) -> Option<Intent> {
        Some(Intent {
            action: Kind::FastForward,
            expected_revision: revision.into(),
            expected_reference_revision: self.expected_reference_revision.clone(),
            expected_ref: reference.into(),
            expected_head: head.into(),
            expected_index: old_index.into(),
            target_ref: self.target_ref.clone(),
            target_oid: self.target_oid.clone(),
            candidate_index: index.into(),
            original_head: shared::hash(format!("ref: {reference}\n").as_bytes()),
            original_head_log: self.head_log.original_sha256.clone(),
            original_branch_log: self.branch_log.original_sha256.clone(),
            head_log_enabled: self.head_log.enabled,
            branch_log_enabled: self.branch_log.enabled,
            footprint: self.footprint.clone()?,
        })
    }
}
pub(crate) fn effect(publication: local::Publication) -> Option<&'static str> {
    use local::Publication::*;
    match publication {
        NotReported => Some("not-published"),
        FfWorktreeReturned => Some("worktree-returned"),
        FfIndexReturned => Some("index-returned"),
        FfRefReturned => Some("ref-returned"),
        _ => None,
    }
}
fn retained_path(p: &str) -> bool {
    let values: Vec<_> = p.split('/').collect();
    values.len() == 3
        && values[0] == ".git"
        && values[1].strip_prefix("mrk-git-").is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
        && matches!(values[2], "index" | "execution-index" | "checkout-mode")
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FinalData {
    pub(crate) effect_phase: String,
    pub(crate) retained_paths: Vec<String>,
}
impl FinalData {
    pub(crate) fn valid(&self) -> bool {
        matches!(
            self.effect_phase.as_str(),
            "worktree-returned" | "index-returned" | "ref-returned"
        ) && self.retained_paths.len() <= 5
            && self.retained_paths.iter().all(|p| retained_path(p))
            && self.retained_paths.windows(2).all(|v| v[0] < v[1])
    }
    pub(crate) fn successful(&self) -> bool {
        self.valid() && self.effect_phase == "ref-returned" && self.retained_paths.is_empty()
    }
    pub(crate) fn from_returned(
        request: &local::Request,
        candidate: &local::Candidate,
        terminal: &local::Terminal,
        publication: local::Publication,
    ) -> Result<Self, BridgeError> {
        need(
            request.phase == local::Phase::Apply
                && request.action.kind() == local::Kind::FastForward
                && terminal.phase == local::Phase::Apply
                && terminal.action == local::Kind::FastForward
                && terminal.status == read::Outcome::Ok
                && terminal.child_declared_settled()
                && terminal.publication == publication
                && publication != local::Publication::NotReported
                && request
                    .binding
                    .as_ref()
                    .is_some_and(|b| candidate.intent.matches(&b.review))
                && terminal.result["operationId"] == request.id
                && terminal.result["intent"]
                    == serde_json::to_value(&candidate.intent)
                        .map_err(|_| BridgeError::protocol())?,
        )?;
        validate_applied(request, terminal, Some(candidate))?;
        let value = Self {
            effect_phase: terminal.result["effectPhase"]
                .as_str()
                .ok_or_else(BridgeError::protocol)?
                .into(),
            retained_paths: terminal.result["retainedPaths"]
                .as_array()
                .ok_or_else(BridgeError::protocol)?
                .iter()
                .map(|p| {
                    p.as_str()
                        .map(str::to_owned)
                        .ok_or_else(BridgeError::protocol)
                })
                .collect::<Result<_, _>>()?,
        };
        need(value.valid())?;
        Ok(value)
    }
}
pub(crate) fn validate_applied(
    request: &local::Request,
    terminal: &local::Terminal,
    candidate: Option<&local::Candidate>,
) -> Result<(), BridgeError> {
    let value = &terminal.result;
    let phase = effect(terminal.publication).ok_or_else(BridgeError::protocol)?;
    need(value["effectPhase"].as_str() == Some(phase))?;
    let retained = value["retainedPaths"]
        .as_array()
        .filter(|v| v.len() <= 5)
        .ok_or_else(BridgeError::protocol)?;
    need(
        retained
            .iter()
            .all(|v| v.as_str().is_some_and(retained_path))
            && retained.windows(2).all(|v| v[0].as_str() < v[1].as_str()),
    )?;
    let intent = candidate.and_then(|c| c.intent.fast_forward_details());
    need(terminal.publication == local::Publication::NotReported || intent.is_some())?;
    if value["state"] == "succeeded" {
        let i = intent.ok_or_else(BridgeError::protocol)?;
        need(
            terminal.publication == local::Publication::FfRefReturned
                && retained.is_empty()
                && value["reason"].is_null()
                && read::observation(&value["observation"])
                && value["observation"]["head"].as_str() == Some(i.target_oid.as_str())
                && value["observation"]["branch"].as_str() == Some(i.expected_ref.as_str())
                && terminal.first_failure_ns.is_none()
                && terminal.cleanup_end_ns == request.clock.hard_end_ns,
        )
    } else {
        need(
            value["reason"]
                .as_str()
                .is_some_and(|v| read::reason(v) || reason(v))
                && value["observation"].is_null()
                && terminal.first_failure_ns.is_some()
                && if value["state"] == "recovery-required" {
                    intent.is_some()
                } else {
                    value["state"] == "failed"
                        && terminal.publication == local::Publication::NotReported
                        && retained.is_empty()
                },
        )
    }
}

#[cfg(test)]
#[path = "git_fast_forward_protocol_tests.rs"]
pub(crate) mod tests;
