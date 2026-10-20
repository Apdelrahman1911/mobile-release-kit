//! One ordinary Push of committed objects to an existing configured upstream.
//! These closed comparisons never issue a credential, start Git, authorize a
//! send, or prove native settlement. The original GitLocal owner does all four.
use crate::{
    git_fetch_protocol as remote, git_read_protocol as read, github_connection_protocol as github,
    protocol::valid_id,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const BODY_LIMIT: u64 = 32 * 1024 * 1024;
pub(crate) const METADATA_LIMIT: u64 = 256 * 1024;
pub(crate) const COMMAND_LIMIT: u64 = 64 * 1024;
pub(crate) const COMMIT_LIMIT: usize = 64;
pub(crate) const STAGING_RESERVE: usize = 80 * 1024 * 1024;
pub(crate) const ACTION_KEYS: &[&str] = &[
    "kind",
    "expectedRevision",
    "expectedReferenceRevision",
    "remote",
    "localRef",
    "remoteRef",
    "oldOid",
    "newOid",
    "connectionSessionId",
    "expectedConnectionRevision",
];
pub(crate) const REVIEW_KEYS: &[&str] = &[
    "action",
    "remote",
    "repository",
    "accountId",
    "repositoryId",
    "login",
    "branch",
    "head",
    "upstreamRef",
    "expectedRemoteOid",
    "trackingRef",
    "commits",
    "expectedRevision",
    "expectedReferenceRevision",
    "expectedIndex",
    "basis",
    "withheld",
    "reviewDigest",
];
pub(crate) const INTENT_KEYS: &[&str] = &[
    "action",
    "reviewDigest",
    "expectedRevision",
    "expectedReferenceRevision",
    "expectedIndex",
    "remote",
    "repository",
    "accountId",
    "repositoryId",
    "localRef",
    "remoteRef",
    "oldOid",
    "newOid",
    "commitsSha256",
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

pub(crate) fn reason(v: &str) -> bool {
    matches!(
        v,
        "push-upstream"
            | "push-history"
            | "push-policy"
            | "push-output"
            | "push-target-changed"
            | "push-remote-refused"
            | "remote-rejected"
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
pub(crate) fn tracking(remote: &str, upstream: &str) -> Option<String> {
    if !remote::remote(remote) || !remote::reference(upstream) {
        return None;
    }
    Some(format!(
        "refs/remotes/{remote}/{}",
        upstream.strip_prefix("refs/heads/")?
    ))
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Kind {
    #[serde(rename = "push")]
    Push,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind: Kind,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) remote: String,
    pub(crate) local_ref: String,
    pub(crate) remote_ref: String,
    pub(crate) old_oid: String,
    pub(crate) new_oid: String,
    pub(crate) connection_session_id: String,
    pub(crate) expected_connection_revision: u32,
}
impl Action {
    pub(crate) fn valid(&self) -> bool {
        read::digest(&self.expected_revision)
            && read::digest(&self.expected_reference_revision)
            && remote::remote(&self.remote)
            && remote::reference(&self.local_ref)
            && remote::reference(&self.remote_ref)
            && remote::oid(&self.old_oid)
            && remote::oid(&self.new_oid)
            && self.old_oid != self.new_oid
            && valid_id(&self.connection_session_id)
            && (1..u32::MAX).contains(&self.expected_connection_revision)
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) action: Kind,
    pub(crate) remote: String,
    pub(crate) repository: String,
    pub(crate) account_id: String,
    pub(crate) repository_id: String,
    pub(crate) login: String,
    pub(crate) branch: String,
    pub(crate) head: String,
    pub(crate) upstream_ref: String,
    pub(crate) expected_remote_oid: String,
    pub(crate) tracking_ref: String,
    pub(crate) commits: Vec<String>,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) expected_index: String,
    pub(crate) basis: String,
    pub(crate) withheld: Vec<String>,
    pub(crate) review_digest: String,
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        tracking(&self.remote, &self.upstream_ref).as_deref() == Some(self.tracking_ref.as_str())
            && github::coordinate(&self.repository)
            && github::numeric_id(&self.account_id)
            && github::numeric_id(&self.repository_id)
            && remote::login(&self.login)
            && remote::reference(&self.branch)
            && remote::oid(&self.head)
            && remote::oid(&self.expected_remote_oid)
            && self.head != self.expected_remote_oid
            && (1..=COMMIT_LIMIT).contains(&self.commits.len())
            && self.commits.last() == Some(&self.head)
            && self.commits.iter().enumerate().all(|(i, v)| {
                remote::oid(v) && v != &self.expected_remote_oid && !self.commits[..i].contains(v)
            })
            && read::digest(&self.expected_revision)
            && read::digest(&self.expected_reference_revision)
            && read::digest(&self.expected_index)
            && read::digest(&self.review_digest)
            && self.basis == "existing-configured-upstream"
            && self.withheld == ["messages", "authors", "emails", "signatures", "objects"]
    }
    pub(crate) fn matches(&self, action: &Action) -> bool {
        self.valid()
            && action.valid()
            && self.remote == action.remote
            && self.expected_revision == action.expected_revision
            && self.expected_reference_revision == action.expected_reference_revision
            && self.branch == action.local_ref
            && self.upstream_ref == action.remote_ref
            && self.expected_remote_oid == action.old_oid
            && self.head == action.new_oid
    }
    pub(crate) fn commits_sha256(&self) -> String {
        let mut hash = Sha256::new();
        for oid in &self.commits {
            hash.update(oid.as_bytes());
            hash.update(b"\n");
        }
        hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Intent {
    pub(crate) action: Kind,
    pub(crate) review_digest: String,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) expected_index: String,
    pub(crate) remote: String,
    pub(crate) repository: String,
    pub(crate) account_id: String,
    pub(crate) repository_id: String,
    pub(crate) local_ref: String,
    pub(crate) remote_ref: String,
    pub(crate) old_oid: String,
    pub(crate) new_oid: String,
    pub(crate) commits_sha256: String,
}
impl Intent {
    pub(crate) fn valid(&self) -> bool {
        read::digest(&self.review_digest)
            && read::digest(&self.expected_revision)
            && read::digest(&self.expected_reference_revision)
            && read::digest(&self.expected_index)
            && read::digest(&self.commits_sha256)
            && remote::remote(&self.remote)
            && github::coordinate(&self.repository)
            && github::numeric_id(&self.account_id)
            && github::numeric_id(&self.repository_id)
            && remote::reference(&self.local_ref)
            && remote::reference(&self.remote_ref)
            && remote::oid(&self.old_oid)
            && remote::oid(&self.new_oid)
            && self.old_oid != self.new_oid
    }
    pub(crate) fn matches(&self, r: &Review) -> bool {
        self.valid()
            && r.valid()
            && self.review_digest == r.review_digest
            && self.expected_revision == r.expected_revision
            && self.expected_reference_revision == r.expected_reference_revision
            && self.expected_index == r.expected_index
            && self.remote == r.remote
            && self.repository == r.repository
            && self.account_id == r.account_id
            && self.repository_id == r.repository_id
            && self.local_ref == r.branch
            && self.remote_ref == r.upstream_ref
            && self.old_oid == r.expected_remote_oid
            && self.new_oid == r.head
            && self.commits_sha256 == r.commits_sha256()
    }
    pub(crate) fn matches_action(&self, a: &Action) -> bool {
        self.valid()
            && a.valid()
            && self.expected_revision == a.expected_revision
            && self.expected_reference_revision == a.expected_reference_revision
            && self.remote == a.remote
            && self.local_ref == a.local_ref
            && self.remote_ref == a.remote_ref
            && self.old_oid == a.old_oid
            && self.new_oid == a.new_oid
    }
}

/// Progress DATA only. Neither a child terminal nor this enum clears a send
/// fence; the actual original native/HTTP/channel/Store joins are independent.
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Effect {
    NotSent,
    CandidateEntered,
    CandidateAcknowledged,
    SendEntered,
    SendConsumed,
    RemoteReturned,
}
pub(crate) fn retained_path(v: &str) -> bool {
    let part = |value: &str, prefix: &str| {
        value.strip_prefix(prefix).is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 32
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
    };
    // Review owns a flat view; Apply nests its view under the SAME original
    // index transaction. These are diagnostics, never a path to reopen/clean.
    match v.split_once('/') {
        Some((parent, child)) => part(parent, "mrk-git-") && part(child, "mrk-git-push-"),
        None => part(v, "mrk-git-push-"),
    }
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
    pub(crate) fn valid(&self, action: &Action, id: &str) -> bool {
        valid_id(id)
            && self.operation_id == id
            && action.valid()
            && self.observation.is_none()
            && self.settlement == "settled"
            && self
                .intent
                .as_ref()
                .is_none_or(|i| i.matches_action(action))
            && self.retained_paths.len() <= 1
            && self.retained_paths.iter().all(|p| retained_path(p))
            && match self.state.as_str() {
                "succeeded" => {
                    self.intent.is_some()
                        && self.reason.is_none()
                        && self.effect_phase == Effect::RemoteReturned
                        && self.retained_paths.is_empty()
                }
                "failed" | "recovery-required" => {
                    self.reason
                        .as_deref()
                        .is_some_and(|v| read::reason(v) || reason(v))
                        && (self.intent.is_some() || self.effect_phase == Effect::NotSent)
                }
                _ => false,
            }
    }
}

#[cfg(test)]
#[path = "git_push_protocol_tests.rs"]
pub(crate) mod tests;
