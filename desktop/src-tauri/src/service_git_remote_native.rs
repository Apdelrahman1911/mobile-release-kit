//! Fixed adapters into the existing GitLocal/Connection owners. These helpers
//! compare originals under Doc; they do not start transport or lend a token.
use super::*;
use crate::{
    git_fetch_protocol as fetch, git_push_protocol as push,
    github_connection_session::{fetch::Pins as FetchPins, push::Pins as PushPins},
};

pub(in crate::asset_session) enum Approval {
    Fetch(FetchPins),
    Push(PushPins),
}
impl Approval {
    pub(super) fn select(
        state: &DocumentState,
        project: &str,
        generation: u32,
        selected: &remote::Action,
        at: Instant,
    ) -> Result<Self, BridgeError> {
        let end = at
            .checked_add(Duration::from_secs(local::WORK_SECONDS))
            .ok_or_else(BridgeError::timeout)?;
        let value = match action(selected)? {
            local::Action::Fetch(a) => Self::Fetch(
                state
                    .github
                    .select_git_fetch(project, generation, &a, at, end)?,
            ),
            local::Action::Push(a) => Self::Push(
                state
                    .github
                    .select_git_push(project, generation, &a, at, end)?,
            ),
            _ => return Err(BridgeError::invalid()),
        };
        let heap = match &value {
            Self::Fetch(p) => p.heap(),
            Self::Push(p) => p.heap(),
        }
        .ok_or_else(BridgeError::cleanup_unknown)?;
        if heap > remote::PINS_HEAP {
            return Err(BridgeError::invalid());
        }
        Ok(value)
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Fetch(a), Self::Fetch(b)) => a == b,
            (Self::Push(a), Self::Push(b)) => a == b,
            _ => false,
        }
    }
    pub(super) fn matches(&self, fetch: Option<&FetchPins>, push: Option<&PushPins>) -> bool {
        match (self, fetch, push) {
            (Self::Fetch(a), Some(b), None) => a == b,
            (Self::Push(a), None, Some(b)) => a == b,
            _ => false,
        }
    }
    pub(super) fn account(&self) -> Result<remote::Account, BridgeError> {
        let account = match self {
            Self::Fetch(p) => {
                let t = p.target(None)?;
                remote::Account {
                    account_id: t.account_id,
                    login: t.login,
                    repository_id: t.repository_id,
                    repository: t.repository,
                }
            }
            Self::Push(p) => {
                let t = p.target(None)?;
                remote::Account {
                    account_id: t.account_id,
                    login: t.login,
                    repository_id: t.repository_id,
                    repository: t.repository,
                }
            }
        };
        if account.valid() {
            Ok(account)
        } else {
            Err(BridgeError::invalid())
        }
    }
    pub(super) fn idle_current(
        &self,
        state: &DocumentState,
        selected: &remote::Action,
        now: Instant,
    ) -> bool {
        match (self, action(selected)) {
            (Self::Fetch(p), Ok(local::Action::Fetch(a))) => {
                state.github.git_fetch_delegation_current(p, &a, now)
            }
            (Self::Push(p), Ok(local::Action::Push(a))) => {
                state.github.git_push_delegation_current(p, &a, now)
            }
            _ => false,
        }
    }
}
pub(super) fn action(selected: &remote::Action) -> Result<local::Action, BridgeError> {
    selected.validate().map_err(public)?;
    let action = match selected {
        remote::Action::Fetch {
            expected_revision,
            expected_reference_revision,
            remote,
            reference,
            connection_session_id,
            expected_connection_revision,
        } => local::Action::Fetch(fetch::Action {
            kind: fetch::Kind::Fetch,
            expected_revision: expected_revision.clone(),
            expected_reference_revision: expected_reference_revision.clone(),
            remote: remote.clone(),
            reference: reference.clone(),
            connection_session_id: connection_session_id.clone(),
            expected_connection_revision: *expected_connection_revision,
        }),
        remote::Action::Push {
            expected_revision,
            expected_reference_revision,
            remote,
            local_ref,
            remote_ref,
            old_oid,
            new_oid,
            connection_session_id,
            expected_connection_revision,
        } => local::Action::Push(push::Action {
            kind: push::Kind::Push,
            expected_revision: expected_revision.clone(),
            expected_reference_revision: expected_reference_revision.clone(),
            remote: remote.clone(),
            local_ref: local_ref.clone(),
            remote_ref: remote_ref.clone(),
            old_oid: old_oid.clone(),
            new_oid: new_oid.clone(),
            connection_session_id: connection_session_id.clone(),
            expected_connection_revision: *expected_connection_revision,
        }),
    };
    if action.valid() {
        Ok(action)
    } else {
        Err(BridgeError::invalid())
    }
}
pub(in crate::asset_session) fn review(
    scope: &requests::NativeScope,
    original: &local::Review,
    review_id: String,
    document_revision: u32,
    generation: u32,
) -> Option<remote::Review> {
    if !original.valid()
        || document_revision != scope.document_revision
        || generation != scope.registration
    {
        return None;
    }
    let shared::Selected::Remote(selected) = &scope.selection else {
        return None;
    };
    let action = action(&selected.action).ok()?;
    let (account, preview) = match (original, &action) {
        (local::Review::Fetch(r), local::Action::Fetch(a)) if r.matches(a) => (
            remote::Account {
                account_id: r.account_id.clone(),
                login: r.login.clone(),
                repository_id: r.repository_id.clone(),
                repository: r.repository.clone(),
            },
            remote::Preview::Fetch {
                target_ref: r.target_ref.clone(),
                expected_target: r.expected_target.clone(),
                candidate_ref_oid: r.candidate_ref_oid.clone(),
            },
        ),
        (local::Review::Push(r), local::Action::Push(a)) if r.matches(a) => (
            remote::Account {
                account_id: r.account_id.clone(),
                login: r.login.clone(),
                repository_id: r.repository_id.clone(),
                repository: r.repository.clone(),
            },
            remote::Preview::Push {
                branch: r.branch.clone(),
                upstream_ref: r.upstream_ref.clone(),
                expected_remote_oid: r.expected_remote_oid.clone(),
                head: r.head.clone(),
                commit_count: u32::try_from(r.commits.len()).ok()?,
                commits_sha256: r.commits_sha256(),
            },
        ),
        _ => return None,
    };
    if account != selected.account {
        return None;
    }
    let (source_revision, reference_revision) = selected.action.revisions();
    let result = remote::Review {
        review_id,
        source_revision: source_revision.into(),
        reference_revision: reference_revision.into(),
        expected_index: original.expected_index()?.into(),
        review_digest: original.review_digest().into(),
        document_revision,
        registration_generation: generation,
        preview,
    };
    result.matches(selected).then_some(result)
}
fn effect_state(v: &str) -> Result<remote::EffectState, BridgeError> {
    match v {
        "succeeded" => Ok(remote::EffectState::Succeeded),
        "failed" => Ok(remote::EffectState::Failed),
        "recovery-required" => Ok(remote::EffectState::RecoveryRequired),
        _ => Err(BridgeError::cleanup_unknown()),
    }
}
/// The caller has already obtained the original native receipt. Deserialize
/// only its fixed mutation DATA (no clone of raw JSON, no paths opened). The
/// bounded original temporary fields are covered by document_backing().
pub(in crate::asset_session) fn outcome(
    scope: &requests::NativeScope,
    view: &local::Projection,
) -> Result<Option<remote::Outcome>, BridgeError> {
    if view.phase != local::Phase::Apply || view.result.is_null() {
        return Ok(None);
    }
    if view.stage != read::Phase::Settled {
        return Err(BridgeError::cleanup_unknown());
    }
    let shared::Selected::Remote(selected) = &scope.selection else {
        return Err(BridgeError::invalid());
    };
    let value = match action(&selected.action)? {
        local::Action::Fetch(a) => {
            let r = fetch::Mutation::deserialize(&view.result)
                .map_err(|_| BridgeError::cleanup_unknown())?;
            if !r.valid(&a, &view.operation_id) {
                return Err(BridgeError::cleanup_unknown());
            }
            let effect = match r.effect_phase {
                fetch::Effect::NotPublished => remote::Effect::NotPublished,
                fetch::Effect::PackLinkEntered => remote::Effect::PackLinkEntered,
                fetch::Effect::PackLinked => remote::Effect::PackLinked,
                fetch::Effect::IndexLinkEntered => remote::Effect::IndexLinkEntered,
                fetch::Effect::ObjectsLinked => remote::Effect::ObjectsLinked,
                fetch::Effect::RefSendEntered => remote::Effect::RefSendEntered,
                fetch::Effect::RefPublished => remote::Effect::RefPublished,
            };
            remote::Outcome {
                operation_id: r.operation_id,
                action: remote::Kind::Fetch,
                state: effect_state(&r.state)?,
                effect_phase: effect,
                retained_paths: r.retained_paths,
            }
        }
        local::Action::Push(a) => {
            let r = push::Mutation::deserialize(&view.result)
                .map_err(|_| BridgeError::cleanup_unknown())?;
            if !r.valid(&a, &view.operation_id) {
                return Err(BridgeError::cleanup_unknown());
            }
            let effect = match r.effect_phase {
                push::Effect::NotSent => remote::Effect::NotSent,
                push::Effect::CandidateEntered => remote::Effect::CandidateEntered,
                push::Effect::CandidateAcknowledged => remote::Effect::CandidateAcknowledged,
                push::Effect::SendEntered => remote::Effect::SendEntered,
                push::Effect::SendConsumed => remote::Effect::SendConsumed,
                push::Effect::RemoteReturned => remote::Effect::RemoteReturned,
            };
            remote::Outcome {
                operation_id: r.operation_id,
                action: remote::Kind::Push,
                state: effect_state(&r.state)?,
                effect_phase: effect,
                retained_paths: r.retained_paths,
            }
        }
        _ => return Err(BridgeError::invalid()),
    };
    if value.valid() {
        Ok(Some(value))
    } else {
        Err(BridgeError::cleanup_unknown())
    }
}
