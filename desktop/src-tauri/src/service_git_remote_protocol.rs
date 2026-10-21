//! Closed Remote comparison DATA for the existing Git inbox. The CLI receives
//! neither a credential, a URL/command choice nor a native review capability.
//! Every kind uses the original selected Desktop Connection. Create-only
//! publication is separate consent, never inferred from a zero old OID.
use crate::{
    service_git_protocol as p,
    service_protocol::{Error, Id, OperationState, Settlement},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RAW_LIMIT: usize = 8 * 1024;
pub const ACCESS_LIMIT: usize = 8 * 1024;
// Includes simultaneous pending/public/private summaries and the final effect
// in ONE existing row. The native full review is charged by GitLocal, not here.
pub(crate) const ROW_HEAP: usize = 24 * 1024;
pub(crate) const PINS_HEAP: usize = 4 * 1024;
pub(crate) const NEW_BRANCH_ZERO: &str = "0000000000000000000000000000000000000000";
pub(crate) const NEW_BRANCH_BASIS: &str = "first-publication-no-upstream";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Fetch,
    Push,
    PushNewBranch,
}
impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::Push => "push",
            Self::PushNewBranch => "push-new-branch",
        }
    }
    pub(crate) fn consent(self) -> &'static str {
        match self {
            Self::Fetch => "agent-git-fetch-once-v1",
            Self::Push => "agent-git-push-once-v1",
            Self::PushNewBranch => "agent-git-push-new-branch-once-v1",
        }
    }
}
pub(crate) fn remote(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.as_bytes()[0].is_ascii_alphanumeric()
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
pub(crate) fn reference(v: &str) -> bool {
    v.is_ascii()
        && v.len() <= 255
        && v.starts_with("refs/heads/")
        && v.split('/').count() <= 32
        && !v.contains("..")
        && !v.contains("@{")
        && !v
            .chars()
            .any(|c| c <= ' ' || c == '\u{7f}' || "~^:?*[\\".contains(c))
        && v.split('/').all(|s| {
            !s.is_empty() && !s.starts_with('.') && !s.ends_with('.') && !s.ends_with(".lock")
        })
}
pub(crate) fn oid(v: &str) -> bool {
    v.len() == 40
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && v.bytes().any(|b| b != b'0')
}
fn numeric(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 20
        && v.bytes().all(|b| b.is_ascii_digit())
        && v.as_bytes()[0] != b'0'
        && v.parse::<u64>().is_ok()
}
fn login(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 39
        && v.as_bytes()[0].is_ascii_alphanumeric()
        && v.as_bytes()[v.len() - 1].is_ascii_alphanumeric()
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn coordinate(v: &str) -> bool {
    let Some((owner, repo)) = v.split_once('/') else {
        return false;
    };
    login(owner)
        && !repo.is_empty()
        && repo.len() <= 100
        && !matches!(repo, "." | "..")
        && repo.as_bytes()[0].is_ascii_alphanumeric()
        && repo.as_bytes()[repo.len() - 1].is_ascii_alphanumeric()
        && repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn tracking(remote: &str, reference: &str) -> Option<String> {
    (self::remote(remote) && self::reference(reference))
        .then(|| format!("refs/remotes/{remote}/{}", &reference[11..]))
}
fn exact(v: String) -> String {
    v.into_boxed_str().into_string()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Action {
    Fetch {
        expected_revision: String,
        expected_reference_revision: String,
        remote: String,
        reference: String,
        connection_session_id: String,
        expected_connection_revision: u32,
    },
    Push {
        expected_revision: String,
        expected_reference_revision: String,
        remote: String,
        local_ref: String,
        remote_ref: String,
        old_oid: String,
        new_oid: String,
        connection_session_id: String,
        expected_connection_revision: u32,
    },
    PushNewBranch {
        expected_revision: String,
        expected_reference_revision: String,
        #[serde(deserialize_with = "required_nullable")]
        remote: Option<String>,
        local_ref: String,
        remote_ref: String,
        old_oid: String,
        new_oid: String,
        connection_session_id: String,
        expected_connection_revision: u32,
    },
}
impl Action {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Fetch { .. } => Kind::Fetch,
            Self::Push { .. } => Kind::Push,
            Self::PushNewBranch { .. } => Kind::PushNewBranch,
        }
    }
    pub(crate) fn revisions(&self) -> (&str, &str) {
        match self {
            Self::Fetch {
                expected_revision,
                expected_reference_revision,
                ..
            }
            | Self::Push {
                expected_revision,
                expected_reference_revision,
                ..
            }
            | Self::PushNewBranch {
                expected_revision,
                expected_reference_revision,
                ..
            } => (expected_revision, expected_reference_revision),
        }
    }
    pub fn remote(&self) -> Option<&str> {
        match self {
            Self::Fetch { remote, .. } | Self::Push { remote, .. } => Some(remote),
            Self::PushNewBranch { remote, .. } => remote.as_deref(),
        }
    }
    pub fn reference(&self) -> &str {
        match self {
            Self::Fetch { reference, .. } => reference,
            Self::Push { remote_ref, .. } | Self::PushNewBranch { remote_ref, .. } => remote_ref,
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        let (revision, refs) = self.revisions();
        let (session, connection_revision, specific) = match self {
            Self::Fetch {
                reference,
                connection_session_id,
                expected_connection_revision,
                ..
            } => (
                connection_session_id,
                *expected_connection_revision,
                self::reference(reference),
            ),
            Self::Push {
                local_ref,
                remote_ref,
                old_oid,
                new_oid,
                connection_session_id,
                expected_connection_revision,
                ..
            } => (
                connection_session_id,
                *expected_connection_revision,
                reference(local_ref)
                    && reference(remote_ref)
                    && oid(old_oid)
                    && oid(new_oid)
                    && old_oid != new_oid,
            ),
            Self::PushNewBranch {
                remote,
                local_ref,
                remote_ref,
                old_oid,
                new_oid,
                connection_session_id,
                expected_connection_revision,
                ..
            } => (
                connection_session_id,
                *expected_connection_revision,
                remote.is_none()
                    && reference(local_ref)
                    && local_ref == remote_ref
                    && old_oid == NEW_BRANCH_ZERO
                    && oid(new_oid),
            ),
        };
        if p::digest(revision)
            && p::digest(refs)
            && self.remote().is_none_or(remote)
            && p::native_id(session)
            && session.len() <= 64
            && (1..u32::MAX).contains(&connection_revision)
            && specific
        {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
    fn compact(self) -> Self {
        match self {
            Self::Fetch {
                expected_revision,
                expected_reference_revision,
                remote,
                reference,
                connection_session_id,
                expected_connection_revision,
            } => Self::Fetch {
                expected_revision: exact(expected_revision),
                expected_reference_revision: exact(expected_reference_revision),
                remote: exact(remote),
                reference: exact(reference),
                connection_session_id: exact(connection_session_id),
                expected_connection_revision,
            },
            Self::Push {
                expected_revision,
                expected_reference_revision,
                remote,
                local_ref,
                remote_ref,
                old_oid,
                new_oid,
                connection_session_id,
                expected_connection_revision,
            } => Self::Push {
                expected_revision: exact(expected_revision),
                expected_reference_revision: exact(expected_reference_revision),
                remote: exact(remote),
                local_ref: exact(local_ref),
                remote_ref: exact(remote_ref),
                old_oid: exact(old_oid),
                new_oid: exact(new_oid),
                connection_session_id: exact(connection_session_id),
                expected_connection_revision,
            },
            Self::PushNewBranch {
                expected_revision,
                expected_reference_revision,
                remote,
                local_ref,
                remote_ref,
                old_oid,
                new_oid,
                connection_session_id,
                expected_connection_revision,
            } => Self::PushNewBranch {
                expected_revision: exact(expected_revision),
                expected_reference_revision: exact(expected_reference_revision),
                remote: remote.map(exact),
                local_ref: exact(local_ref),
                remote_ref: exact(remote_ref),
                old_oid: exact(old_oid),
                new_oid: exact(new_oid),
                connection_session_id: exact(connection_session_id),
                expected_connection_revision,
            },
        }
    }
    pub(crate) fn history_action(&self) -> crate::service_protocol::Action {
        match self.kind() {
            Kind::Fetch => crate::service_protocol::Action::GitFetch,
            Kind::Push => crate::service_protocol::Action::GitPush,
            Kind::PushNewBranch => crate::service_protocol::Action::GitPushNewBranch,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Account {
    pub account_id: String,
    pub login: String,
    pub repository_id: String,
    pub repository: String,
}
impl Account {
    pub(crate) fn valid(&self) -> bool {
        numeric(&self.account_id)
            && login(&self.login)
            && numeric(&self.repository_id)
            && coordinate(&self.repository)
    }
    fn compact(self) -> Self {
        Self {
            account_id: exact(self.account_id),
            login: exact(self.login),
            repository_id: exact(self.repository_id),
            repository: exact(self.repository),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selection {
    pub action: Action,
    pub account: Account,
    pub selection_sha256: String,
}
impl Selection {
    pub(crate) fn new(action: Action, account: Account) -> Result<Self, Error> {
        action.validate()?;
        if !account.valid() {
            return Err(Error::InvalidRequest);
        }
        let mut hash = Sha256::new();
        hash.update(b"mrk-agent-git-remote-selection/1\0");
        let bytes = serde_json::to_vec(&(&action, &account)).map_err(|_| Error::InvalidRequest)?;
        if bytes.len() > 2304 {
            return Err(Error::InvalidRequest);
        }
        hash.update(bytes);
        Ok(Self {
            action: action.compact(),
            account: account.compact(),
            selection_sha256: crate::service_protocol::hex(&hash.finalize()),
        })
    }
    pub fn validate(&self) -> Result<(), Error> {
        if Self::new(self.action.clone(), self.account.clone())?.selection_sha256
            == self.selection_sha256
        {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
}
fn required_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
pub type Query = p::Query;
pub type Prepare = p::Prepare;
pub type Start = p::Start;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Access {
    pub enabled: bool,
    pub remaining_ms: u64,
    pub consumed: bool,
    #[serde(deserialize_with = "required_nullable")]
    pub project_id: Option<Id>,
    #[serde(deserialize_with = "required_nullable")]
    pub grant_id: Option<Id>,
    #[serde(deserialize_with = "required_nullable")]
    pub selection: Option<Selection>,
}
impl Access {
    pub(crate) fn empty() -> Self {
        Self::from_parts(p::Access::<Selection>::empty_shared())
    }
    pub(crate) fn from_parts(v: p::Access<Selection>) -> Self {
        Self {
            enabled: v.enabled,
            remaining_ms: v.remaining_ms,
            consumed: v.consumed,
            project_id: v.project_id,
            grant_id: v.grant_id,
            selection: v.selection,
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        p::access_shape(
            self.enabled,
            self.remaining_ms,
            self.consumed,
            self.project_id.is_some(),
            self.grant_id.is_some(),
            self.selection.is_some(),
        )?;
        if let Some(s) = &self.selection {
            s.validate()?;
        }
        p::encoded_bound(self, ACCESS_LIMIT - 1024)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    pub service_instance: Id,
    pub project_id: Id,
    pub access: Access,
}
impl Scope {
    pub fn validate(&self) -> Result<(), Error> {
        self.access.validate()?;
        if self
            .access
            .project_id
            .as_ref()
            .is_some_and(|p| p != &self.project_id)
        {
            return Err(Error::InvalidRequest);
        }
        p::encoded_bound(self, ACCESS_LIMIT - 512)
    }
}

/// Only a bounded projection of the SAME native review. Push's complete
/// outgoing list stays in that owner; count+digest do not claim object safety.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Preview {
    Fetch {
        target_ref: String,
        #[serde(deserialize_with = "required_nullable")]
        expected_target: Option<String>,
        candidate_ref_oid: String,
    },
    Push {
        branch: String,
        upstream_ref: String,
        expected_remote_oid: String,
        head: String,
        commit_count: u32,
        commits_sha256: String,
    },
    PushNewBranch {
        branch: String,
        target_ref: String,
        expected_remote_oid: String,
        head: String,
        commit_count: u32,
        commits_sha256: String,
        basis: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Review {
    pub review_id: String,
    pub source_revision: String,
    pub reference_revision: String,
    pub expected_index: String,
    pub review_digest: String,
    pub document_revision: u32,
    pub registration_generation: u32,
    pub preview: Preview,
}
impl Review {
    pub(crate) fn matches(&self, selection: &Selection) -> bool {
        if selection.validate().is_err()
            || !p::native_id(&self.review_id)
            || !p::digest(&self.expected_index)
            || !p::digest(&self.review_digest)
            || !(1..u32::MAX).contains(&self.document_revision)
            || !(1..u32::MAX).contains(&self.registration_generation)
            || selection.action.revisions()
                != (
                    self.source_revision.as_str(),
                    self.reference_revision.as_str(),
                )
        {
            return false;
        }
        match (&self.preview, &selection.action) {
            (
                Preview::Fetch {
                    target_ref,
                    expected_target,
                    candidate_ref_oid,
                },
                Action::Fetch {
                    remote, reference, ..
                },
            ) => {
                tracking(remote, reference).as_deref() == Some(target_ref.as_str())
                    && expected_target.as_deref().is_none_or(oid)
                    && oid(candidate_ref_oid)
            }
            (
                Preview::Push {
                    branch,
                    upstream_ref,
                    expected_remote_oid,
                    head,
                    commit_count,
                    commits_sha256,
                },
                Action::Push {
                    local_ref,
                    remote_ref,
                    old_oid,
                    new_oid,
                    ..
                },
            ) => {
                branch == local_ref
                    && upstream_ref == remote_ref
                    && expected_remote_oid == old_oid
                    && head == new_oid
                    && (1..=64).contains(commit_count)
                    && p::digest(commits_sha256)
            }
            (
                Preview::PushNewBranch {
                    branch,
                    target_ref,
                    expected_remote_oid,
                    head,
                    commit_count,
                    commits_sha256,
                    basis,
                },
                Action::PushNewBranch {
                    local_ref,
                    remote_ref,
                    old_oid,
                    new_oid,
                    ..
                },
            ) => {
                branch == local_ref
                    && target_ref == remote_ref
                    && expected_remote_oid == old_oid
                    && expected_remote_oid == NEW_BRANCH_ZERO
                    && head == new_oid
                    && (1..=64).contains(commit_count)
                    && p::digest(commits_sha256)
                    && basis == NEW_BRANCH_BASIS
            }
            _ => false,
        }
    }
    pub(crate) fn can_apply(&self) -> bool {
        match &self.preview {
            Preview::Fetch {
                expected_target,
                candidate_ref_oid,
                ..
            } => expected_target.as_ref() != Some(candidate_ref_oid),
            Preview::Push { .. } | Preview::PushNewBranch { .. } => true,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Effect {
    NotPublished,
    PackLinkEntered,
    PackLinked,
    IndexLinkEntered,
    ObjectsLinked,
    RefSendEntered,
    RefPublished,
    NotSent,
    CandidateEntered,
    CandidateAcknowledged,
    SendEntered,
    SendConsumed,
    RemoteReturned,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectState {
    Succeeded,
    Failed,
    RecoveryRequired,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Outcome {
    pub operation_id: String,
    pub action: Kind,
    pub state: EffectState,
    pub effect_phase: Effect,
    pub retained_paths: Vec<String>,
}
impl Outcome {
    pub(crate) fn valid(&self) -> bool {
        let part = |v: &str, prefix: &str| {
            v.strip_prefix(prefix).is_some_and(|s| {
                !s.is_empty()
                    && s.len() <= 32
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            })
        };
        p::native_id(&self.operation_id)
            && self.retained_paths.windows(2).all(|p| p[0] < p[1])
            && match self.action {
                Kind::Fetch => {
                    matches!(
                        self.effect_phase,
                        Effect::NotPublished
                            | Effect::PackLinkEntered
                            | Effect::PackLinked
                            | Effect::IndexLinkEntered
                            | Effect::ObjectsLinked
                            | Effect::RefSendEntered
                            | Effect::RefPublished
                    ) && self.retained_paths.len() <= 5
                        && self.retained_paths.iter().all(|v| {
                            part(v, "mrk-git-fetch-")
                                || v.strip_prefix("objects/pack/pack-").is_some_and(|s| {
                                    s.split_once('.').is_some_and(|(hash, ext)| {
                                        oid(hash) && matches!(ext, "pack" | "idx" | "keep")
                                    })
                                })
                        })
                        && (self.state != EffectState::Succeeded
                            || self.effect_phase == Effect::RefPublished
                                && self.retained_paths.is_empty())
                }
                Kind::Push | Kind::PushNewBranch => {
                    matches!(
                        self.effect_phase,
                        Effect::NotSent
                            | Effect::CandidateEntered
                            | Effect::CandidateAcknowledged
                            | Effect::SendEntered
                            | Effect::SendConsumed
                            | Effect::RemoteReturned
                    ) && self.retained_paths.len() <= 1
                        && self.retained_paths.iter().all(|v| match v.split_once('/') {
                            Some((p, c)) => part(p, "mrk-git-") && part(c, "mrk-git-push-"),
                            None => part(v, "mrk-git-push-"),
                        })
                        && (self.state != EffectState::Succeeded
                            || self.effect_phase == Effect::RemoteReturned
                                && self.retained_paths.is_empty())
                }
            }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub progress: p::Status<Selection, Review>,
    #[serde(deserialize_with = "required_nullable")]
    pub result: Option<Outcome>,
}
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        let p = &self.progress;
        p.selection.validate()?;
        p.validate_progress()?;
        if p.review.as_ref().is_some_and(|r| {
            !r.matches(&p.selection)
                || r.review_id.strip_suffix("-review") != p.prepare_operation_id.as_deref()
        }) {
            return Err(Error::InvalidRequest);
        }
        if let Some(result) = &self.result {
            if !result.valid()
                || p.settlement != Settlement::Settled
                || p.apply_operation_id.as_deref() != Some(result.operation_id.as_str())
                || p.selection.action.kind() != result.action
                || p.review.is_some()
                || p.outcome
                    != Some(match result.state {
                        EffectState::Succeeded => OperationState::Succeeded,
                        EffectState::Failed => OperationState::Failed,
                        EffectState::RecoveryRequired => OperationState::RecoveryRequired,
                    })
            {
                return Err(Error::InvalidRequest);
            }
        }
        // Envelope allowance is included. Never truncate a review or silently
        // turn an over-limit/unknown response into another request.
        p::encoded_bound(self, p::STATUS_BYTES - 512)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn selection(push: bool) -> Selection {
        let action = if push {
            Action::Push {
                expected_revision: "a".repeat(64),
                expected_reference_revision: "b".repeat(64),
                remote: "origin".into(),
                local_ref: "refs/heads/main".into(),
                remote_ref: "refs/heads/main".into(),
                old_oid: "c".repeat(40),
                new_oid: "d".repeat(40),
                connection_session_id: "connection-1".into(),
                expected_connection_revision: 3,
            }
        } else {
            Action::Fetch {
                expected_revision: "a".repeat(64),
                expected_reference_revision: "b".repeat(64),
                remote: "origin".into(),
                reference: "refs/heads/main".into(),
                connection_session_id: "connection-1".into(),
                expected_connection_revision: 3,
            }
        };
        Selection::new(
            action,
            Account {
                account_id: "11".into(),
                login: "fixture".into(),
                repository_id: "22".into(),
                repository: "fixture/repo".into(),
            },
        )
        .unwrap()
    }
    pub(crate) fn review(push: bool) -> Review {
        Review {
            review_id: "git-local-1-review".into(),
            source_revision: "a".repeat(64),
            reference_revision: "b".repeat(64),
            expected_index: "e".repeat(64),
            review_digest: "f".repeat(64),
            document_revision: 1,
            registration_generation: 1,
            preview: if push {
                Preview::Push {
                    branch: "refs/heads/main".into(),
                    upstream_ref: "refs/heads/main".into(),
                    expected_remote_oid: "c".repeat(40),
                    head: "d".repeat(40),
                    commit_count: 64,
                    commits_sha256: "6".repeat(64),
                }
            } else {
                Preview::Fetch {
                    target_ref: "refs/remotes/origin/main".into(),
                    expected_target: Some("c".repeat(40)),
                    candidate_ref_oid: "d".repeat(40),
                }
            },
        }
    }
    pub(crate) fn new_branch_selection() -> Selection {
        Selection::new(
            Action::PushNewBranch {
                expected_revision: "a".repeat(64),
                expected_reference_revision: "b".repeat(64),
                remote: None,
                local_ref: "refs/heads/main".into(),
                remote_ref: "refs/heads/main".into(),
                old_oid: NEW_BRANCH_ZERO.into(),
                new_oid: "d".repeat(40),
                connection_session_id: "connection-1".into(),
                expected_connection_revision: 3,
            },
            selection(true).account,
        )
        .unwrap()
    }
    pub(crate) fn new_branch_review() -> Review {
        Review {
            preview: Preview::PushNewBranch {
                branch: "refs/heads/main".into(),
                target_ref: "refs/heads/main".into(),
                expected_remote_oid: NEW_BRANCH_ZERO.into(),
                head: "d".repeat(40),
                commit_count: 64,
                commits_sha256: "6".repeat(64),
                basis: NEW_BRANCH_BASIS.into(),
            },
            ..review(true)
        }
    }
    #[test]
    fn new_branch_is_explicit_required_null_and_never_an_ordinary_grant() {
        let s = new_branch_selection();
        let value = serde_json::to_value(&s.action).unwrap();
        assert!(value["remote"].is_null());
        assert!(s.validate().is_ok());
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("remote");
        assert!(serde_json::from_value::<Action>(missing).is_err());
        for (key, bad) in [
            ("remote", serde_json::json!("origin")),
            ("kind", serde_json::json!("push")),
            ("oldOid", serde_json::json!("c".repeat(40))),
            ("newOid", serde_json::json!(NEW_BRANCH_ZERO)),
            ("remoteRef", serde_json::json!("refs/heads/other")),
            ("setUpstream", serde_json::json!(true)),
            ("force", serde_json::json!(false)),
            ("url", serde_json::json!("https://github.com/other/repo")),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            assert!(
                !serde_json::from_value::<Action>(changed).is_ok_and(|a| a.validate().is_ok()),
                "{key}"
            );
        }
        assert!(new_branch_review().matches(&s));
        for old in [false, true] {
            assert!(!review(old).matches(&s));
            assert!(!new_branch_review().matches(&selection(old)));
            assert_ne!(
                s.action.kind().consent(),
                selection(old).action.kind().consent()
            );
        }
        assert_eq!(
            s.action.history_action(),
            crate::service_protocol::Action::GitPushNewBranch
        );
    }
    #[test]
    fn adding_new_kind_preserves_old_selection_bytes_and_digest_domain() {
        for (push, digest) in [
            (
                false,
                "d3ddd1568fdab2f9932981c73857d4ba8eddaeff26b3c6a9a65147455ddfddb1",
            ),
            (
                true,
                "b1bbd43fd23d6f961012f952a68b06bff5d9e178e8f831bfe51a25b270ecac3b",
            ),
        ] {
            let old = selection(push);
            assert_eq!(old.selection_sha256, digest);
            assert_eq!(
                serde_json::to_value(&old.action).unwrap()["remote"],
                "origin"
            );
            assert_ne!(
                new_branch_selection().selection_sha256,
                old.selection_sha256
            );
        }
    }
    #[test]
    fn create_only_review_and_result_cannot_launder_kind_basis_or_effect() {
        let selected = new_branch_selection();
        for which in 0..5 {
            let mut r = new_branch_review();
            if let Preview::PushNewBranch {
                basis,
                expected_remote_oid,
                target_ref,
                commit_count,
                ..
            } = &mut r.preview
            {
                match which {
                    0 => *basis = "existing-configured-upstream".into(),
                    1 => *expected_remote_oid = "c".repeat(40),
                    2 => *target_ref = "refs/heads/other".into(),
                    3 => *commit_count = 0,
                    _ => *commit_count = 65,
                }
            }
            assert!(!r.matches(&selected));
        }
        let id = Id::parse(&"a".repeat(32)).unwrap();
        let mut status = Status {
            progress: p::Status {
                origin: Query {
                    project_id: id.clone(),
                    service_instance: id.clone(),
                    request_id: id.clone(),
                },
                grant_id: id,
                selection: selected,
                revision: 3,
                state: p::State::Finished,
                prepare_operation_id: Some("git-local-1".into()),
                apply_operation_id: Some("git-local-2".into()),
                review: None,
                outcome: Some(OperationState::RecoveryRequired),
                settlement: Settlement::Settled,
                reason: Some(p::Reason::RecoveryRequired),
                history_available: false,
                do_not_replay: true,
            },
            result: Some(Outcome {
                operation_id: "git-local-2".into(),
                action: Kind::PushNewBranch,
                state: EffectState::RecoveryRequired,
                effect_phase: Effect::SendConsumed,
                retained_paths: vec!["mrk-git-x/mrk-git-push-y".into()],
            }),
        };
        assert!(status.validate().is_ok());
        status.result.as_mut().unwrap().action = Kind::Push;
        assert!(status.validate().is_err());
        status.result.as_mut().unwrap().action = Kind::PushNewBranch;
        status.result.as_mut().unwrap().effect_phase = Effect::RefPublished;
        assert!(status.validate().is_err());
        status.result.as_mut().unwrap().effect_phase = Effect::SendConsumed;
        status.progress.settlement = Settlement::Unknown;
        assert!(status.validate().is_err());
    }
    #[test]
    fn create_only_escaped_summary_keeps_existing_encoded_bound() {
        let long = format!("refs/heads/{}", "\"".repeat(244));
        let mut s = new_branch_selection();
        if let Action::PushNewBranch {
            local_ref,
            remote_ref,
            ..
        } = &mut s.action
        {
            *local_ref = long.clone();
            *remote_ref = long.clone();
        }
        s = Selection::new(s.action, s.account).unwrap();
        let mut r = new_branch_review();
        if let Preview::PushNewBranch {
            branch, target_ref, ..
        } = &mut r.preview
        {
            *branch = long.clone();
            *target_ref = long;
        }
        assert!(r.matches(&s));
        let id = Id::parse(&"a".repeat(32)).unwrap();
        let value = Status {
            progress: p::Status {
                origin: Query {
                    project_id: id.clone(),
                    service_instance: id.clone(),
                    request_id: id.clone(),
                },
                grant_id: id,
                selection: s,
                revision: 1,
                state: p::State::Prepared,
                prepare_operation_id: Some("git-local-1".into()),
                apply_operation_id: None,
                review: Some(r),
                outcome: None,
                settlement: Settlement::Pending,
                reason: None,
                history_available: false,
                do_not_replay: true,
            },
            result: None,
        };
        assert!(value.validate().is_ok());
        assert!(serde_json::to_vec(&value).unwrap().len() < p::STATUS_BYTES - 512);
    }
    #[test]
    fn fixed_actions_and_digest_refuse_authority_or_cross_family_additions() {
        for push in [false, true] {
            let s = selection(push);
            assert!(s.validate().is_ok());
            assert!(review(push).matches(&s));
            assert!(!review(!push).matches(&s));
            let mut changed = s.clone();
            changed.account.account_id = "33".into();
            assert!(changed.validate().is_err());
            let mut json = serde_json::to_value(&s.action).unwrap();
            json["force"] = true.into();
            assert!(serde_json::from_value::<Action>(json).is_err());
        }
        assert!(!remote("origin/other"));
        assert!(!reference("refs/heads/../main"));
        assert!(!oid(&"0".repeat(40)));
        assert!(!coordinate("https://github.com/a/b"));
        assert!(!numeric("01"));
    }
    #[test]
    fn required_null_access_and_fetch_preview_never_default_missing_fields() {
        let empty = Access::empty();
        assert!(empty.validate().is_ok());
        for key in ["projectId", "grantId", "selection"] {
            let mut v = serde_json::to_value(&empty).unwrap();
            v.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<Access>(v).is_err());
        }
        let mut r = review(false);
        let mut missing = serde_json::to_value(&r.preview).unwrap();
        missing.as_object_mut().unwrap().remove("expectedTarget");
        assert!(serde_json::from_value::<Preview>(missing).is_err());
        if let Preview::Fetch {
            expected_target,
            candidate_ref_oid,
            ..
        } = &mut r.preview
        {
            *expected_target = Some(candidate_ref_oid.clone());
        }
        assert!(r.matches(&selection(false)));
        assert!(!r.can_apply());
    }
    #[test]
    fn effects_are_diagnostics_not_paths_or_a_success_upgrade() {
        let mut v = Outcome {
            operation_id: "git-local-2".into(),
            action: Kind::Push,
            state: EffectState::RecoveryRequired,
            effect_phase: Effect::SendEntered,
            retained_paths: vec!["mrk-git-fixture/mrk-git-push-fixture".into()],
        };
        assert!(v.valid());
        v.state = EffectState::Succeeded;
        assert!(!v.valid());
        v.effect_phase = Effect::RemoteReturned;
        v.retained_paths.clear();
        assert!(v.valid());
        v.action = Kind::Fetch;
        assert!(!v.valid());
        v.state = EffectState::RecoveryRequired;
        v.effect_phase = Effect::PackLinked;
        v.retained_paths = vec!["/tmp/private".into()];
        assert!(!v.valid());
    }
    #[test]
    fn bounded_maximum_reference_summary_remains_below_status_envelope() {
        let mut s = selection(true);
        let long = format!("refs/heads/{}", "\"".repeat(244));
        if let Action::Push {
            local_ref,
            remote_ref,
            ..
        } = &mut s.action
        {
            *local_ref = long.clone();
            *remote_ref = long.clone();
        }
        s = Selection::new(s.action, s.account).unwrap();
        let mut r = review(true);
        if let Preview::Push {
            branch,
            upstream_ref,
            ..
        } = &mut r.preview
        {
            *branch = long.clone();
            *upstream_ref = long;
        }
        let id = Id::parse(&"a".repeat(32)).unwrap();
        let status = Status {
            progress: p::Status {
                origin: Query {
                    project_id: id.clone(),
                    service_instance: id.clone(),
                    request_id: id.clone(),
                },
                grant_id: id,
                selection: s,
                revision: 1,
                state: p::State::Prepared,
                prepare_operation_id: Some("git-local-1".into()),
                apply_operation_id: None,
                review: Some(r),
                outcome: None,
                settlement: Settlement::Pending,
                reason: None,
                history_available: false,
                do_not_replay: true,
            },
            result: None,
        };
        assert!(status.validate().is_ok());
        assert!(serde_json::to_vec(&status).unwrap().len() < p::STATUS_BYTES - 512);
        let mut missing = serde_json::to_value(&status).unwrap();
        missing.as_object_mut().unwrap().remove("result");
        assert!(serde_json::from_value::<Status>(missing).is_err());
    }
}
