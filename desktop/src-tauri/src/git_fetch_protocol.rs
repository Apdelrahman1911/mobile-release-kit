//! Closed Fetch DATA on the existing GitLocal five-command surface.
//! Account/session numbers are comparisons, not token, consent or source
//! authority. Only the original selected ConnectionState supplies the private
//! Target. Prepare includes an explicit remote read; Apply uses its same review.
use crate::{git_read_protocol as read, github_connection_protocol as github, protocol::valid_id};
use serde::{Deserialize, Serialize};

pub(crate) const FILE_LIMIT: u64 = 32 * 1024 * 1024;
pub(crate) const STAGING_RESERVE: usize = 80 * 1024 * 1024;
pub(crate) const ACTION_KEYS: &[&str] = &[
    "kind",
    "expectedRevision",
    "expectedReferenceRevision",
    "remote",
    "reference",
    "connectionSessionId",
    "expectedConnectionRevision",
];
pub(crate) const REVIEW_KEYS: &[&str] = &[
    "action",
    "remote",
    "repository",
    "reference",
    "targetRef",
    "expectedTarget",
    "candidateRefOid",
    "expectedRevision",
    "expectedReferenceRevision",
    "head",
    "branch",
    "expectedIndex",
    "accountId",
    "repositoryId",
    "login",
    "reviewDigest",
];
pub(crate) const INTENT_KEYS: &[&str] = &[
    "action",
    "reviewDigest",
    "expectedRevision",
    "expectedReferenceRevision",
    "expectedRef",
    "expectedHead",
    "expectedIndex",
    "targetRef",
    "expectedTarget",
    "candidateRefOid",
    "packOid",
    "packSha256",
    "packBytes",
    "indexSha256",
    "indexBytes",
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

pub(crate) fn remote(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.as_bytes()[0].is_ascii_alphanumeric()
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
pub(crate) fn reference(v: &str) -> bool {
    v.is_ascii() && v.len() <= 255 && v.split('/').count() <= 32 && read::branch(v)
}
pub(crate) fn oid(v: &str) -> bool {
    v.len() == 40
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && v.bytes().any(|b| b != b'0')
}
pub(crate) fn login(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 39
        && v.as_bytes()[0].is_ascii_alphanumeric()
        && v.as_bytes()[v.len() - 1].is_ascii_alphanumeric()
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
pub(crate) fn reason(v: &str) -> bool {
    matches!(
        v,
        "fetch-remote"
            | "fetch-layout"
            | "fetch-identity-required"
            | "fetch-ref-parent"
            | "fetch-output"
            | "fetch-object-limit"
            | "fetch-target-changed"
            | "fetch-up-to-date"
            | "unsupported-protocol"
            | "target-changed"
            | "network-unavailable"
            | "tls-failed"
            | "unauthorized"
            | "forbidden"
            | "not-found-or-inaccessible"
            | "rate-limited"
            | "expired"
            | "cancelled"
            | "cleanup-unknown"
    )
}
fn tracking(remote: &str, selected: &str) -> Option<String> {
    if !self::remote(remote) || !reference(selected) {
        return None;
    }
    Some(format!(
        "refs/remotes/{remote}/{}",
        selected.strip_prefix("refs/heads/")?
    ))
}
fn tracking_ref(v: &str) -> bool {
    let Some(tail) = v.strip_prefix("refs/remotes/") else {
        return false;
    };
    let Some((name, branch)) = tail.split_once('/') else {
        return false;
    };
    remote(name) && reference(&format!("refs/heads/{branch}"))
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Kind {
    #[serde(rename = "fetch")]
    Fetch,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind: Kind,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) remote: String,
    pub(crate) reference: String,
    pub(crate) connection_session_id: String,
    pub(crate) expected_connection_revision: u32,
}
impl Action {
    pub(crate) fn valid(&self) -> bool {
        read::digest(&self.expected_revision)
            && read::digest(&self.expected_reference_revision)
            && remote(&self.remote)
            && reference(&self.reference)
            && valid_id(&self.connection_session_id)
            && self.expected_connection_revision > 0
            && self.expected_connection_revision < u32::MAX
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) action: Kind,
    pub(crate) remote: String,
    pub(crate) repository: String,
    pub(crate) reference: String,
    pub(crate) target_ref: String,
    pub(crate) expected_target: Option<String>,
    pub(crate) candidate_ref_oid: String,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) head: Option<String>,
    pub(crate) branch: Option<String>,
    pub(crate) expected_index: String,
    pub(crate) account_id: String,
    pub(crate) repository_id: String,
    pub(crate) login: String,
    pub(crate) review_digest: String,
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        tracking(&self.remote, &self.reference).as_deref() == Some(self.target_ref.as_str())
            && github::coordinate(&self.repository)
            && oid(&self.candidate_ref_oid)
            && self.expected_target.as_deref().is_none_or(oid)
            && self.head.as_deref().is_none_or(oid)
            && self.branch.as_deref().is_none_or(read::branch)
            && (self.head.is_some() || self.branch.is_some())
            && read::digest(&self.expected_revision)
            && read::digest(&self.expected_reference_revision)
            && read::digest(&self.expected_index)
            && read::digest(&self.review_digest)
            && github::numeric_id(&self.account_id)
            && github::numeric_id(&self.repository_id)
            && login(&self.login)
    }
    pub(crate) fn matches(&self, action: &Action) -> bool {
        self.valid()
            && action.valid()
            && self.remote == action.remote
            && self.reference == action.reference
            && self.expected_revision == action.expected_revision
            && self.expected_reference_revision == action.expected_reference_revision
    }
    /// This is display/Apply-refusal DATA. It is not a fresh network request.
    pub(crate) fn up_to_date(&self) -> bool {
        self.valid() && self.expected_target.as_deref() == Some(self.candidate_ref_oid.as_str())
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Intent {
    pub(crate) action: Kind,
    pub(crate) review_digest: String,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) expected_ref: Option<String>,
    pub(crate) expected_head: Option<String>,
    pub(crate) expected_index: String,
    pub(crate) target_ref: String,
    pub(crate) expected_target: Option<String>,
    pub(crate) candidate_ref_oid: String,
    pub(crate) pack_oid: String,
    pub(crate) pack_sha256: String,
    pub(crate) pack_bytes: u64,
    pub(crate) index_sha256: String,
    pub(crate) index_bytes: u64,
}
impl Intent {
    pub(crate) fn valid(&self) -> bool {
        read::digest(&self.review_digest)
            && read::digest(&self.expected_revision)
            && read::digest(&self.expected_reference_revision)
            && read::digest(&self.expected_index)
            && self.expected_ref.as_deref().is_none_or(read::branch)
            && self.expected_head.as_deref().is_none_or(oid)
            && (self.expected_ref.is_some() || self.expected_head.is_some())
            && tracking_ref(&self.target_ref)
            && self.expected_target.as_deref().is_none_or(oid)
            && oid(&self.candidate_ref_oid)
            && self.expected_target.as_deref() != Some(self.candidate_ref_oid.as_str())
            && oid(&self.pack_oid)
            && read::digest(&self.pack_sha256)
            && read::digest(&self.index_sha256)
            && (1..=FILE_LIMIT).contains(&self.pack_bytes)
            && (1..=FILE_LIMIT).contains(&self.index_bytes)
    }
    pub(crate) fn matches(&self, review: &Review) -> bool {
        self.valid()
            && review.valid()
            && self.review_digest == review.review_digest
            && self.expected_revision == review.expected_revision
            && self.expected_reference_revision == review.expected_reference_revision
            && self.expected_ref == review.branch
            && self.expected_head == review.head
            && self.expected_index == review.expected_index
            && self.target_ref == review.target_ref
            && self.expected_target == review.expected_target
            && self.candidate_ref_oid == review.candidate_ref_oid
    }
}

/// Child progress cannot authorize SourceBook successor adoption or final CAS.
/// Native uses only the actual original publication/joins, never this enum.
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Effect {
    NotPublished,
    PackLinkEntered,
    PackLinked,
    IndexLinkEntered,
    ObjectsLinked,
    RefSendEntered,
    RefPublished,
}
pub(crate) fn retained_path(v: &str, intent: Option<&Intent>) -> bool {
    if let Some(tail) = v.strip_prefix("mrk-git-fetch-") {
        return !tail.is_empty()
            && tail.len() <= 32
            && tail
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    }
    let Some(intent) = intent else {
        return false;
    };
    ["pack", "idx", "keep"]
        .iter()
        .any(|suffix| v == format!("objects/pack/pack-{}.{suffix}", intent.pack_oid))
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Mutation {
    pub(crate) operation_id: String,
    pub(crate) action: Kind,
    pub(crate) state: String,
    pub(crate) settlement: String,
    pub(crate) reason: Option<String>,
    pub(crate) observation: Option<serde_json::Value>,
    pub(crate) intent: Option<Intent>,
    pub(crate) effect_phase: Effect,
    pub(crate) retained_paths: Vec<String>,
}
impl Mutation {
    pub(crate) fn valid(&self, action: &Action, operation_id: &str) -> bool {
        valid_id(operation_id)
            && self.operation_id == operation_id
            && action.valid()
            && self.observation.is_none()
            && self.settlement == "settled"
            && self.intent.as_ref().is_none_or(|i| {
                i.valid()
                    && i.expected_revision == action.expected_revision
                    && i.expected_reference_revision == action.expected_reference_revision
                    && tracking(&action.remote, &action.reference).as_deref()
                        == Some(i.target_ref.as_str())
            })
            && self.retained_paths.len() <= 5
            && self.retained_paths.windows(2).all(|r| r[0] < r[1])
            && self
                .retained_paths
                .iter()
                .all(|p| retained_path(p, self.intent.as_ref()))
            && match self.state.as_str() {
                "succeeded" => {
                    self.intent.is_some()
                        && self.reason.is_none()
                        && self.effect_phase == Effect::RefPublished
                        && self.retained_paths.is_empty()
                }
                "failed" | "recovery-required" => {
                    self.reason
                        .as_deref()
                        .is_some_and(|v| read::reason(v) || reason(v))
                        && (self.intent.is_some() || self.effect_phase == Effect::NotPublished)
                }
                _ => false,
            }
    }
}

#[cfg(test)]
#[path = "git_fetch_protocol_tests.rs"]
pub(crate) mod tests;
