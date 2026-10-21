//! Closed first-publication comparisons in the SAME Push protocol. A zero OID
//! is never a mode selector, an observed absence, or permission to overwrite.
use super::*;

pub(crate) const ZERO: &str = "0000000000000000000000000000000000000000";
pub(crate) const BASIS: &str = "first-publication-no-upstream";

/// Explicit null is required for the two absent configuration fields. Missing
/// keys must not become a first-publication request through Option's default.
pub(super) fn nullable<'de, T, D>(d: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(d)
}

impl Kind {
    pub(crate) fn local_kind(self) -> crate::git_local_protocol::Kind {
        match self {
            Self::Push => crate::git_local_protocol::Kind::Push,
            Self::PushNewBranch => crate::git_local_protocol::Kind::PushNewBranch,
        }
    }

    pub(super) fn source(
        self,
        alias: Option<&str>,
        local: &str,
        target: &str,
        old: &str,
        new: &str,
    ) -> bool {
        remote::reference(local)
            && remote::reference(target)
            && remote::oid(new)
            && old != new
            && match self {
                Self::Push => alias.is_some_and(remote::remote) && remote::oid(old),
                Self::PushNewBranch => alias.is_none() && old == ZERO && local == target,
            }
    }

    pub(super) fn review_source(self, r: &Review) -> bool {
        self.source(
            r.remote.as_deref(),
            &r.branch,
            &r.upstream_ref,
            &r.expected_remote_oid,
            &r.head,
        ) && match self {
            Self::Push => {
                r.basis == "existing-configured-upstream"
                    && r.remote
                        .as_deref()
                        .and_then(|alias| tracking(alias, &r.upstream_ref))
                        .as_deref()
                        == r.tracking_ref.as_deref()
            }
            Self::PushNewBranch => r.basis == BASIS && r.tracking_ref.is_none(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn action() -> Action {
        let mut action = super::super::tests::action();
        action.kind = Kind::PushNewBranch;
        action.remote = None;
        action.remote_ref = action.local_ref.clone();
        action.old_oid = ZERO.into();
        action
    }

    pub(crate) fn review() -> Review {
        let mut review = super::super::tests::review();
        review.action = Kind::PushNewBranch;
        review.remote = None;
        review.upstream_ref = review.branch.clone();
        review.tracking_ref = None;
        review.expected_remote_oid = ZERO.into();
        review.basis = BASIS.into();
        review
    }

    pub(crate) fn intent() -> Intent {
        let mut intent = super::super::tests::intent();
        let review = review();
        intent.action = review.action;
        intent.remote = None;
        intent.remote_ref = review.upstream_ref;
        intent.old_oid = ZERO.into();
        intent
    }

    #[test]
    fn first_publication_is_explicit_and_ordinary_push_stays_nonzero() {
        let a = action();
        let r = review();
        let i = intent();
        assert!(a.valid() && r.matches(&a) && i.matches(&r) && i.matches_action(&a));
        let mut ordinary = a.clone();
        ordinary.kind = Kind::Push;
        assert!(!ordinary.valid());
        let mut forged = a.clone();
        forged.remote = Some("origin".into());
        assert!(!forged.valid());
        forged = a.clone();
        forged.remote_ref = "refs/heads/another".into();
        assert!(!forged.valid());
        forged = a.clone();
        forged.old_oid = "a".repeat(40);
        assert!(!forged.valid());
        assert!(!r.matches(&super::super::tests::action()));
        assert!(!i.matches(&super::super::tests::review()));
        assert!(!super::super::tests::intent().matches_action(&a));
    }

    #[test]
    fn null_configuration_is_required_never_missing_or_fabricated() {
        let a = serde_json::to_value(action()).unwrap();
        assert!(a["remote"].is_null());
        assert!(serde_json::from_value::<Action>(a.clone()).unwrap().valid());
        let mut missing = a;
        missing.as_object_mut().unwrap().remove("remote");
        assert!(serde_json::from_value::<Action>(missing).is_err());
        let r = serde_json::to_value(review()).unwrap();
        for field in ["remote", "trackingRef"] {
            let mut missing = r.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Review>(missing).is_err());
            let mut invented = r.clone();
            invented[field] = json!(if field == "remote" {
                "origin"
            } else {
                "refs/remotes/origin/main"
            });
            assert!(!serde_json::from_value::<Review>(invented).unwrap().valid());
        }
        let mut wrong = review();
        wrong.basis = "existing-configured-upstream".into();
        assert!(!wrong.valid());
        wrong = review();
        wrong.action = Kind::Push;
        assert!(!wrong.valid());
    }

    #[test]
    fn whole_history_and_mutation_keep_exact_create_only_kind() {
        let a = action();
        let mut r = review();
        r.commits = vec!["3".repeat(40), a.new_oid.clone()];
        assert!(r.matches(&a));
        r.commits.insert(0, ZERO.into());
        assert!(!r.valid());
        r = review();
        r.commits = vec![r.head.clone(); 65];
        assert!(!r.valid());
        let mut mutation = Mutation {
            operation_id: "push-new-1".into(),
            action: Kind::PushNewBranch,
            state: "recovery-required".into(),
            settlement: "settled".into(),
            reason: Some("remote-rejected".into()),
            observation: None,
            intent: Some(intent()),
            effect_phase: Effect::SendConsumed,
            retained_paths: vec!["mrk-git-x/mrk-git-push-y".into()],
        };
        assert!(mutation.valid(&a, "push-new-1"));
        mutation.action = Kind::Push;
        assert!(!mutation.valid(&a, "push-new-1"));
    }
}
