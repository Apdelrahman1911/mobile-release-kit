//! Bounded current-branch rename DATA for the SAME GitLocal owner.
//! These projections never confer a source lock, consent, durable ACK or join.
use crate::{
    error::BridgeError, git_branch_protocol as branch, git_local_protocol as local,
    git_read_protocol as read,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const CONFIG_LIMIT: u64 = 60 * 1024;
pub(crate) const LOG_LIMIT: u64 = 60 * 1024;
pub(crate) const INDEX_LIMIT: u64 = 1024 * 1024;
pub(crate) const REVIEW_KEYS: &[&str] = &[
    "action",
    "name",
    "targetRef",
    "expectedRevision",
    "expectedReferenceRevision",
    "head",
    "branch",
    "expectedIndex",
    "configMoved",
    "logging",
    "originalConfig",
    "originalLog",
    "originalHeadLog",
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
    "expectedTargetAbsent",
    "originalConfig",
    "candidateConfig",
    "originalLog",
    "candidateLog",
    "originalHeadLog",
    "candidateHeadLog",
    "configMoved",
    "logging",
];
pub(crate) const RESULT_KEYS: &[&str] = &[
    "operationId",
    "action",
    "state",
    "settlement",
    "reason",
    "observation",
    "intent",
    "effectPhase",
    "retainedPaths",
];
fn need(value: bool) -> Result<(), BridgeError> {
    if value {
        Ok(())
    } else {
        Err(BridgeError::protocol())
    }
}
pub(crate) fn hash(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub(crate) fn reason(value: &str) -> bool {
    matches!(
        value,
        "rename-layout"
            | "rename-target"
            | "rename-config"
            | "rename-log"
            | "rename-log-missing"
            | "rename-identity-required"
            | "rename-packed"
    )
}
pub(crate) fn same_parent(old: &str, new: &str) -> bool {
    old.strip_prefix("refs/heads/").is_some_and(branch::name)
        && new.strip_prefix("refs/heads/").is_some_and(branch::name)
        && old.rsplit_once('/').map(|v| v.0) == new.rsplit_once('/').map(|v| v.0)
        && !old.eq_ignore_ascii_case(new)
}
fn log_hashes(logging: bool, old: &str, head: &str) -> bool {
    read::digest(old)
        && read::digest(head)
        && (logging || old == hash(b"absent") && head == hash(b"absent"))
}
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Kind {
    #[serde(rename = "branch-rename")]
    Rename,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind: Kind,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) name: String,
}
impl Action {
    pub(crate) fn valid(&self) -> bool {
        branch::name(&self.name)
            && read::digest(&self.expected_revision)
            && read::digest(&self.expected_reference_revision)
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) action: Kind,
    pub(crate) name: String,
    pub(crate) target_ref: String,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) head: String,
    pub(crate) branch: String,
    pub(crate) expected_index: String,
    pub(crate) config_moved: bool,
    pub(crate) logging: bool,
    pub(crate) original_config: String,
    pub(crate) original_log: String,
    pub(crate) original_head_log: String,
    pub(crate) review_digest: String,
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        branch::name(&self.name)
            && self.target_ref == format!("refs/heads/{}", self.name)
            && same_parent(&self.branch, &self.target_ref)
            && read::oid(&self.head)
            && [
                &self.expected_revision,
                &self.expected_reference_revision,
                &self.expected_index,
                &self.original_config,
                &self.review_digest,
            ]
            .iter()
            .all(|v| read::digest(v))
            && log_hashes(self.logging, &self.original_log, &self.original_head_log)
    }
    pub(crate) fn matches(&self, action: &Action) -> bool {
        self.valid()
            && action.valid()
            && self.name == action.name
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
    pub(crate) expected_target_absent: bool,
    pub(crate) original_config: String,
    pub(crate) candidate_config: String,
    pub(crate) original_log: String,
    pub(crate) candidate_log: String,
    pub(crate) original_head_log: String,
    pub(crate) candidate_head_log: String,
    pub(crate) config_moved: bool,
    pub(crate) logging: bool,
}
impl Intent {
    pub(crate) fn valid(&self) -> bool {
        same_parent(&self.expected_ref, &self.target_ref)
            && read::oid(&self.expected_head)
            && self.expected_target_absent
            && [
                &self.expected_revision,
                &self.expected_reference_revision,
                &self.expected_index,
                &self.original_config,
                &self.candidate_config,
            ]
            .iter()
            .all(|v| read::digest(v))
            && (self.config_moved || self.original_config == self.candidate_config)
            && log_hashes(self.logging, &self.original_log, &self.original_head_log)
            && log_hashes(self.logging, &self.candidate_log, &self.candidate_head_log)
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
            && self.original_config == r.original_config
            && self.original_log == r.original_log
            && self.original_head_log == r.original_head_log
            && self.config_moved == r.config_moved
            && self.logging == r.logging
    }
}

// Only the real native SourceBook emits these. No Deserialize/public command.
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefLocks {
    pub(crate) source_identity: read::FileIdentity,
    pub(crate) target_identity: read::FileIdentity,
    pub(crate) parent_before: read::FileIdentity,
    pub(crate) parent_locked: read::FileIdentity,
}
#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Sources {
    pub(crate) source_ref: String,
    pub(crate) ref_locks: RefLocks,
    #[serde(rename = "ref")]
    pub(crate) reference: read::Snapshot,
    pub(crate) branch_log: Option<read::Snapshot>,
    pub(crate) head_log: Option<read::Snapshot>,
}
fn file(s: &read::Snapshot, uid: u32, limit: u64) -> bool {
    let v = s.identity;
    v.0 > 0
        && v.1 > 0
        && v.2 & 0o170000 == 0o100000
        && v.2 & 0o7022 == 0
        && v.3 == uid
        && v.5 == 1
        && v.6 <= limit
        && read::digest(&s.sha256)
}
fn parent(v: read::FileIdentity, uid: u32) -> bool {
    v.0 > 0 && v.1 > 0 && v.2 & 0o170000 == 0o040000 && v.2 & 0o7022 == 0 && v.3 == uid && v.5 > 0
}
pub(crate) fn parent_transition(a: read::FileIdentity, b: read::FileIdentity) -> bool {
    (a.0, a.1, a.2, a.3, a.4, a.5) == (b.0, b.1, b.2, b.3, b.4, b.5)
}
pub(crate) fn moved_original(before: read::FileIdentity, after: read::FileIdentity) -> bool {
    (
        before.0, before.1, before.2, before.3, before.4, before.5, before.6, before.7,
    ) == (
        after.0, after.1, after.2, after.3, after.4, after.5, after.6, after.7,
    ) && before.5 == 1
}
impl Sources {
    pub(crate) fn valid(&self, native: &read::Native, r: &Review) -> bool {
        let locks = &self.ref_locks;
        native.valid()
            && r.valid()
            && self.source_ref == r.branch
            && file(&self.reference, native.uid, 65)
            && self.reference.sha256 == hash(format!("{}\n", r.head).as_bytes())
            && native.files.head.sha256 == hash(format!("ref: {}\n", r.branch).as_bytes())
            && file(&native.files.config, native.uid, CONFIG_LIMIT)
            && native.files.config.sha256 == r.original_config
            && native
                .files
                .index
                .as_ref()
                .is_some_and(|s| file(s, native.uid, INDEX_LIMIT) && s.sha256 == r.expected_index)
            && [locks.source_identity, locks.target_identity]
                .iter()
                .all(|v| {
                    v.2 == 0o100600
                        && file(
                            &read::Snapshot {
                                identity: *v,
                                sha256: hash(b""),
                            },
                            native.uid,
                            0,
                        )
                })
            && (locks.source_identity.0, locks.source_identity.1)
                != (locks.target_identity.0, locks.target_identity.1)
            && parent(locks.parent_before, native.uid)
            && parent(locks.parent_locked, native.uid)
            && parent_transition(locks.parent_before, locks.parent_locked)
            && match (&self.branch_log, &self.head_log) {
                (None, None) => !r.logging,
                (Some(a), Some(b)) => {
                    r.logging
                        && file(a, native.uid, LOG_LIMIT)
                        && file(b, native.uid, LOG_LIMIT)
                        && a.sha256 == r.original_log
                        && b.sha256 == r.original_head_log
                }
                _ => false,
            }
    }
}

/// Schema4 only on explicit rename Preparing; old rows/envelopes stay exact.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CandidateData {
    pub(crate) config: String,
    pub(crate) log: String,
    pub(crate) head_log: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Journal {
    pub(crate) expected_reference_revision: String,
    pub(crate) target_ref: String,
    pub(crate) original_config: String,
    pub(crate) original_log: String,
    pub(crate) original_head_log: String,
    pub(crate) config_moved: bool,
    pub(crate) logging: bool,
    pub(crate) candidate: Option<CandidateData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) final_state: Option<FinalData>,
}
impl Journal {
    pub(crate) fn preparing(r: &Review) -> Self {
        Self {
            expected_reference_revision: r.expected_reference_revision.clone(),
            target_ref: r.target_ref.clone(),
            original_config: r.original_config.clone(),
            original_log: r.original_log.clone(),
            original_head_log: r.original_head_log.clone(),
            config_moved: r.config_moved,
            logging: r.logging,
            candidate: None,
            final_state: None,
        }
    }
    pub(crate) fn valid(&self, head: Option<&str>, reference: Option<&str>) -> bool {
        head.is_some_and(read::oid)
            && reference.is_some_and(|r| same_parent(r, &self.target_ref))
            && read::digest(&self.expected_reference_revision)
            && read::digest(&self.original_config)
            && log_hashes(self.logging, &self.original_log, &self.original_head_log)
            && self.candidate.as_ref().is_none_or(|v| {
                read::digest(&v.config)
                    && (self.config_moved || v.config == self.original_config)
                    && log_hashes(self.logging, &v.log, &v.head_log)
            })
            && self.final_state.as_ref().is_none_or(|v| {
                self.candidate.is_some() && v.valid_for(self.logging, self.config_moved)
            })
    }
    pub(crate) fn same_original(&self, old: &Self) -> bool {
        self.expected_reference_revision == old.expected_reference_revision
            && self.target_ref == old.target_ref
            && self.original_config == old.original_config
            && self.original_log == old.original_log
            && self.original_head_log == old.original_head_log
            && self.config_moved == old.config_moved
            && self.logging == old.logging
    }
    pub(crate) fn accepts(&self, intent: &Intent) -> bool {
        self.candidate.is_none()
            && self.final_state.is_none()
            && intent.valid()
            && self.expected_reference_revision == intent.expected_reference_revision
            && self.target_ref == intent.target_ref
            && self.original_config == intent.original_config
            && self.original_log == intent.original_log
            && self.original_head_log == intent.original_head_log
            && self.config_moved == intent.config_moved
            && self.logging == intent.logging
    }
    pub(crate) fn candidate(&mut self, intent: &Intent) {
        self.candidate = Some(CandidateData {
            config: intent.candidate_config.clone(),
            log: intent.candidate_log.clone(),
            head_log: intent.candidate_head_log.clone(),
        });
    }
    pub(crate) fn intent(
        &self,
        revision: &str,
        reference: &str,
        head: &str,
        index: &str,
    ) -> Option<Intent> {
        let c = self.candidate.as_ref()?;
        Some(Intent {
            action: Kind::Rename,
            expected_revision: revision.into(),
            expected_reference_revision: self.expected_reference_revision.clone(),
            expected_ref: reference.into(),
            expected_head: head.into(),
            expected_index: index.into(),
            target_ref: self.target_ref.clone(),
            expected_target_absent: true,
            original_config: self.original_config.clone(),
            candidate_config: c.config.clone(),
            original_log: self.original_log.clone(),
            candidate_log: c.log.clone(),
            original_head_log: self.original_head_log.clone(),
            candidate_head_log: c.head_log.clone(),
            config_moved: self.config_moved,
            logging: self.logging,
        })
    }
}

pub(crate) fn effect(p: local::Publication) -> Option<&'static str> {
    use local::Publication::*;
    match p {
        NotReported => Some("not-published"),
        RenameNewLogReturned => Some("new-log-returned"),
        RenameOldLogReturned => Some("old-log-returned"),
        RenameRefReturned => Some("ref-returned"),
        RenameHeadLogReturned => Some("head-log-returned"),
        RenameHeadReturned => Some("head-returned"),
        RenameConfigReturned => Some("config-returned"),
        _ => None,
    }
}
pub(crate) fn steps(logging: bool, config: bool) -> &'static [local::Publication] {
    use local::Publication::*;
    match (logging, config) {
        (true, true) => &[
            RenameNewLogReturned,
            RenameOldLogReturned,
            RenameRefReturned,
            RenameHeadLogReturned,
            RenameHeadReturned,
            RenameConfigReturned,
        ],
        (true, false) => &[
            RenameNewLogReturned,
            RenameOldLogReturned,
            RenameRefReturned,
            RenameHeadLogReturned,
            RenameHeadReturned,
        ],
        (false, true) => &[RenameRefReturned, RenameHeadReturned, RenameConfigReturned],
        (false, false) => &[RenameRefReturned, RenameHeadReturned],
    }
}
fn retained_path(path: &str) -> bool {
    let p: Vec<_> = path.split('/').collect();
    p.len() == 3
        && p[0] == ".git"
        && p[2] == "index"
        && p[1].strip_prefix("mrk-git-").is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FinalData {
    pub(crate) effect_phase: String,
    pub(crate) retained_paths: Vec<String>,
}
impl FinalData {
    pub(crate) fn valid_for(&self, logging: bool, config: bool) -> bool {
        steps(logging, config)
            .iter()
            .any(|v| effect(*v) == Some(self.effect_phase.as_str()))
            && self.retained_paths.len() <= 1
            && self.retained_paths.iter().all(|v| retained_path(v))
    }
    pub(crate) fn successful(&self, config: bool) -> bool {
        self.effect_phase
            == (if config {
                "config-returned"
            } else {
                "head-returned"
            })
            && self.retained_paths.is_empty()
    }
    pub(crate) fn from_returned(
        request: &local::Request,
        candidate: &local::Candidate,
        terminal: &local::Terminal,
        publication: local::Publication,
    ) -> Result<Self, BridgeError> {
        need(
            request.phase == local::Phase::Apply
                && request.action.kind() == local::Kind::BranchRename
                && terminal.phase == local::Phase::Apply
                && terminal.action == local::Kind::BranchRename
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
        let intent = candidate
            .intent
            .rename_details()
            .ok_or_else(BridgeError::protocol)?;
        let result = Self {
            effect_phase: terminal.result["effectPhase"]
                .as_str()
                .ok_or_else(BridgeError::protocol)?
                .into(),
            retained_paths: terminal.result["retainedPaths"]
                .as_array()
                .ok_or_else(BridgeError::protocol)?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or_else(BridgeError::protocol)
                })
                .collect::<Result<_, _>>()?,
        };
        need(result.valid_for(intent.logging, intent.config_moved))?;
        Ok(result)
    }
}
pub(crate) fn validate_applied(
    request: &local::Request,
    terminal: &local::Terminal,
    candidate: Option<&local::Candidate>,
) -> Result<(), BridgeError> {
    let value = &terminal.result;
    need(value["effectPhase"].as_str() == effect(terminal.publication))?;
    let retained = value["retainedPaths"]
        .as_array()
        .filter(|v| v.len() <= 1)
        .ok_or_else(BridgeError::protocol)?;
    need(
        retained
            .iter()
            .all(|v| v.as_str().is_some_and(retained_path)),
    )?;
    let intent = candidate.and_then(|v| v.intent.rename_details());
    need(
        terminal.publication == local::Publication::NotReported
            || intent
                .is_some_and(|i| steps(i.logging, i.config_moved).contains(&terminal.publication)),
    )?;
    if value["state"] == "succeeded" {
        let i = intent.ok_or_else(BridgeError::protocol)?;
        need(
            Some(&terminal.publication) == steps(i.logging, i.config_moved).last()
                && retained.is_empty()
                && value["reason"].is_null()
                && read::observation(&value["observation"])
                && value["observation"]["branch"].as_str() == Some(i.target_ref.as_str())
                && value["observation"]["head"].as_str() == Some(i.expected_head.as_str())
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
#[path = "git_rename_protocol_tests.rs"]
pub(crate) mod tests;
