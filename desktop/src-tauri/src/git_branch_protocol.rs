//! Closed branch comparison DATA for the existing GitRead/GitLocal owners.
//! No new native source, journal, execution grant or finality witness. The
//! core alone evaluates repository policy; these types bind its finite result.
use crate::{error::BridgeError, git_read_protocol as read};
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn need(v: bool) -> Result<(), BridgeError> {
    if v { Ok(()) } else { Err(BridgeError::protocol()) }
}
fn keys(v: &Value, names: &[&str]) -> bool {
    v.as_object().is_some_and(|v| v.len() == names.len() && names.iter().all(|n| v.contains_key(*n)))
}
pub(crate) fn name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|c| c.is_ascii_alphanumeric() || b"._/-".contains(&c))
        && value.split('/').count() <= 16 && read::branch(&format!("refs/heads/{value}"))
}
pub(crate) fn reason(value: &str) -> bool {
    matches!(value, "branch-exists" | "branch-parent-missing" | "branch-identity-required" | "unborn-head")
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum Kind { #[serde(rename = "branch-create")] Create }

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
        read::digest(&self.expected_revision) && read::digest(&self.expected_reference_revision) && name(&self.name)
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
    pub(crate) branch: Option<String>,
    pub(crate) expected_index: String,
    pub(crate) review_digest: String,
}
impl Review {
    pub(crate) fn valid(&self) -> bool {
        name(&self.name) && self.target_ref == format!("refs/heads/{}", self.name)
            && read::digest(&self.expected_revision) && read::digest(&self.expected_reference_revision)
            && read::oid(&self.head) && self.branch.as_deref().is_none_or(read::branch)
            && self.branch.as_deref() != Some(self.target_ref.as_str())
            && read::digest(&self.expected_index) && read::digest(&self.review_digest)
    }
    pub(crate) fn matches(&self, selected: &Action) -> bool {
        self.valid() && selected.valid() && self.name == selected.name
            && self.expected_revision == selected.expected_revision
            && self.expected_reference_revision == selected.expected_reference_revision
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Intent {
    pub(crate) action: Kind,
    pub(crate) expected_revision: String,
    pub(crate) expected_reference_revision: String,
    pub(crate) expected_ref: Option<String>,
    pub(crate) expected_head: String,
    pub(crate) expected_index: String,
    pub(crate) target_ref: String,
    pub(crate) expected_target_absent: bool,
    pub(crate) candidate_ref_oid: String,
}
impl Intent {
    pub(crate) fn valid(&self) -> bool {
        read::digest(&self.expected_revision) && read::digest(&self.expected_reference_revision)
            && read::digest(&self.expected_index) && read::oid(&self.expected_head)
            && self.expected_ref.as_deref().is_none_or(read::branch)
            && self.expected_ref.as_deref() != Some(self.target_ref.as_str())
            && self.target_ref.strip_prefix("refs/heads/").is_some_and(name)
            && self.expected_target_absent && self.candidate_ref_oid == self.expected_head
    }
    pub(crate) fn matches(&self, review: &Review) -> bool {
        self.valid() && review.valid() && self.expected_revision == review.expected_revision
            && self.expected_reference_revision == review.expected_reference_revision
            && self.expected_ref == review.branch && self.expected_head == review.head
            && self.expected_index == review.expected_index && self.target_ref == review.target_ref
    }
}

/// Schema2-only addition to the SAME existing per-project operation row.
/// Preparing retains absence and the selected name before any ref effects;
/// candidate_ref_oid is filled only in that original row's candidate CAS.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Journal {
    pub(crate) expected_reference_revision: String,
    pub(crate) target_ref: String,
    pub(crate) expected_target_absent: bool,
    pub(crate) candidate_ref_oid: Option<String>,
}
impl Journal {
    pub(crate) fn preparing(review: &Review) -> Self {
        Self { expected_reference_revision: review.expected_reference_revision.clone(),
            target_ref: review.target_ref.clone(), expected_target_absent: true, candidate_ref_oid: None }
    }
    pub(crate) fn valid(&self, head: Option<&str>) -> bool {
        read::digest(&self.expected_reference_revision) && self.expected_target_absent
            && self.target_ref.strip_prefix("refs/heads/").is_some_and(name)
            && head.is_some_and(read::oid)
            && self.candidate_ref_oid.as_deref().is_none_or(|oid| Some(oid) == head)
    }
    pub(crate) fn same_original(&self, original: &Self) -> bool {
        self.expected_reference_revision == original.expected_reference_revision
            && self.target_ref == original.target_ref && self.expected_target_absent == original.expected_target_absent
    }
    pub(crate) fn accepts(&self, intent: &Intent) -> bool {
        self.candidate_ref_oid.is_none() && intent.valid()
            && self.expected_reference_revision == intent.expected_reference_revision
            && self.target_ref == intent.target_ref && self.expected_target_absent == intent.expected_target_absent
    }
}

pub(crate) fn validate_list(expected_revision: Option<&str>, value: &Value) -> Result<(), BridgeError> {
    need(keys(value, &["revision", "referenceRevision", "head", "branch", "branches", "basis"])
        && expected_revision.is_some_and(read::digest) && value["revision"].as_str() == expected_revision
        && value["referenceRevision"].as_str().is_some_and(read::digest) && value["basis"] == "local-refs-no-fetch"
        && (value["head"].is_null() || value["head"].as_str().is_some_and(read::oid))
        && (value["branch"].is_null() || value["branch"].as_str().is_some_and(read::branch))
        && !(value["head"].is_null() && value["branch"].is_null()))?;
    let rows = value["branches"].as_array().filter(|v| v.len() <= 256).ok_or_else(BridgeError::protocol)?;
    let mut previous: Option<&str> = None;
    let mut width = value["head"].as_str().map(str::len);
    let mut current = None;
    for row in rows {
        need(keys(row, &["ref", "oid"]))?;
        let reference = row["ref"].as_str().filter(|v| read::branch(v) && v.split('/').count() <= 32)
            .ok_or_else(BridgeError::protocol)?;
        let oid = row["oid"].as_str().filter(|v| read::oid(v)).ok_or_else(BridgeError::protocol)?;
        need(previous.is_none_or(|v| v < reference) && width.is_none_or(|w| w == oid.len()))?;
        previous = Some(reference); width = Some(oid.len());
        if value["branch"].as_str() == Some(reference) { current = Some(oid); }
    }
    need(value["branch"].is_null() || current == value["head"].as_str())
}

#[cfg(test)]
#[path = "git_branch_protocol_tests.rs"]
mod tests;
