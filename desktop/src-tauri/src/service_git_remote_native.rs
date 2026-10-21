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
            remote: Some(remote.clone()),
            local_ref: local_ref.clone(),
            remote_ref: remote_ref.clone(),
            old_oid: old_oid.clone(),
            new_oid: new_oid.clone(),
            connection_session_id: connection_session_id.clone(),
            expected_connection_revision: *expected_connection_revision,
        }),
        remote::Action::PushNewBranch {
            expected_revision,
            expected_reference_revision,
            local_ref,
            remote_ref,
            old_oid,
            new_oid,
            connection_session_id,
            expected_connection_revision,
            ..
        } => local::Action::Push(push::Action {
            kind: push::Kind::PushNewBranch,
            expected_revision: expected_revision.clone(),
            expected_reference_revision: expected_reference_revision.clone(),
            remote: None,
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
            match r.action {
                push::Kind::Push => remote::Preview::Push {
                    branch: r.branch.clone(),
                    upstream_ref: r.upstream_ref.clone(),
                    expected_remote_oid: r.expected_remote_oid.clone(),
                    head: r.head.clone(),
                    commit_count: u32::try_from(r.commits.len()).ok()?,
                    commits_sha256: r.commits_sha256(),
                },
                push::Kind::PushNewBranch => remote::Preview::PushNewBranch {
                    branch: r.branch.clone(),
                    target_ref: r.upstream_ref.clone(),
                    expected_remote_oid: r.expected_remote_oid.clone(),
                    head: r.head.clone(),
                    commit_count: u32::try_from(r.commits.len()).ok()?,
                    commits_sha256: r.commits_sha256(),
                    basis: r.basis.clone(),
                },
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
                action: match r.action {
                    push::Kind::Push => remote::Kind::Push,
                    push::Kind::PushNewBranch => remote::Kind::PushNewBranch,
                },
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

#[cfg(test)]
mod tests {
    use super::*;
    // Only the actual protocol's inert Action/Review/Mutation fixtures. No
    // Connection Pins, native receipt, Doc finish or service Ready is minted.
    fn scope() -> (Arc<()>, requests::NativeScope) {
        let doc = Arc::new(());
        let a = push::new_branch::tests::action();
        let r = push::new_branch::tests::review();
        let action = serde_json::from_value(serde_json::to_value(a).unwrap()).unwrap();
        let selected = remote::Selection::new(
            action,
            remote::Account {
                account_id: r.account_id,
                login: r.login,
                repository_id: r.repository_id,
                repository: r.repository,
            },
        )
        .unwrap();
        let scope = requests::NativeScope {
            project_id: crate::service_protocol::Id::parse(&"a".repeat(32)).unwrap(),
            runtime_id: "project-1".into(),
            root: "/inert/new-branch".into(),
            device: 1,
            inode: 2,
            registration: 1,
            document_revision: 1,
            input_revision: 1,
            read_operation_id: Some("git-read-1".into()),
            document: Arc::downgrade(&doc),
            selection: selected.into(),
            commit: None,
            changes: tokio::sync::watch::channel(0).0,
        };
        (doc, scope)
    }
    #[test]
    fn fixed_native_adapter_preserves_new_kind_and_exact_review_not_ordinary_push() {
        let (_doc, scope) = scope();
        let shared::Selected::Remote(s) = &scope.selection else {
            panic!("Remote fixture")
        };
        let a = action(&s.action).unwrap();
        assert!(matches!(&a, local::Action::Push(a) if *a == push::new_branch::tests::action()));
        let original = local::Review::Push(push::new_branch::tests::review());
        let projected = review(&scope, &original, "git-local-1-review".into(), 1, 1).unwrap();
        assert!(
            matches!(&projected.preview, remote::Preview::PushNewBranch {basis, expected_remote_oid, ..}
            if basis == remote::NEW_BRANCH_BASIS && expected_remote_oid == remote::NEW_BRANCH_ZERO)
        );
        assert!(projected.matches(s));
        assert!(review(
            &scope,
            &local::Review::Push(push::tests::review()),
            "git-local-1-review".into(),
            1,
            1
        )
        .is_none());
        let mut foreign = push::new_branch::tests::review();
        foreign.account_id = "99".into();
        assert!(foreign.valid());
        assert!(review(
            &scope,
            &local::Review::Push(foreign),
            "git-local-1-review".into(),
            1,
            1
        )
        .is_none());
        assert!(review(&scope, &original, "git-local-1-review".into(), 2, 1).is_none());
        for push in [false, true] {
            let selected = remote::tests::selection(push).action;
            let native = action(&selected).unwrap();
            assert!(if push {
                matches!(native, local::Action::Push(a) if a.kind == push::Kind::Push && a.remote.as_deref() == Some("origin"))
            } else {
                matches!(native, local::Action::Fetch(_))
            });
        }
    }
    #[test]
    fn new_branch_effect_conversion_checks_original_kind_intent_and_id() {
        let (_doc, scope) = scope();
        let native = local::Action::Push(push::new_branch::tests::action());
        let mutation = push::Mutation {
            operation_id: "git-local-2".into(),
            action: push::Kind::PushNewBranch,
            state: "recovery-required".into(),
            settlement: "settled".into(),
            reason: Some("remote-rejected".into()),
            observation: None,
            intent: Some(push::new_branch::tests::intent()),
            effect_phase: push::Effect::SendConsumed,
            retained_paths: vec!["mrk-git-a/mrk-git-push-b".into()],
        };
        let view = local::Projection {
            operation_id: "git-local-2".into(),
            context: read::Context {
                project_id: "project-1".into(),
                generation: 1,
                revision: "document-1".into(),
            },
            phase: local::Phase::Apply,
            action: native.public(),
            stage: read::Phase::Settled,
            outcome: Some(read::Outcome::Ok),
            reason: None,
            result: serde_json::to_value(mutation).unwrap(),
        };
        let result = outcome(&scope, &view).unwrap().unwrap();
        assert_eq!(result.action, remote::Kind::PushNewBranch);
        assert_eq!(result.state, remote::EffectState::RecoveryRequired);
        assert_eq!(result.effect_phase, remote::Effect::SendConsumed);
        for which in 0..5 {
            let mut bad = view.clone();
            match which {
                0 => bad.result["action"] = "push".into(),
                1 => bad.result["intent"]["action"] = "push".into(),
                2 => bad.result["intent"]["oldOid"] = "1".repeat(40).into(),
                3 => bad.operation_id = "git-local-other".into(),
                _ => bad.stage = read::Phase::CleanupUnknown,
            }
            assert!(outcome(&scope, &bad).is_err(), "{which}");
        }
    }
}
