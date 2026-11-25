//! Five create-only comparisons in the SAME nonshipping Push observer.
//! No original Registration, Connection, process, receipt or clock is made here.
use super::{local, push, read, Value};
use serde_json::json;
use std::path::Path;

pub(super) const SCOPE: &str = "git-push-create-native";
pub(super) const NAMES: [&str; 5] = [
    "git-push-create-empty",
    "git-push-create-equal",
    "git-push-create-stale",
    "git-push-create-race",
    "git-push-create-held",
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Case {
    Empty,
    Equal,
    Stale,
    Race,
    Held,
}
impl Case {
    pub(super) fn name(self) -> &'static str {
        NAMES[self as usize]
    }
    pub(super) fn apply_requested(self) -> bool {
        self != Self::Equal
    }
}

/// Independent fixed before/after comparisons only. SourceBook still holds
/// the original repository during work; absence is never a synthetic FileFact.
pub(super) fn absent_tracking(root: &Path, uid: u32) -> Result<[[u64; 6]; 2], ()> {
    Ok([
        super::super::directory(&root.join(".git/refs"), uid, 0o700, &["heads", "tags"])?,
        super::super::directory(&root.join(".git/logs/refs"), uid, 0o700, &["heads"])?,
    ])
}
pub(super) fn tracking(value: &Value) -> bool {
    let names = [
        "state", "remote", "mergeRef", "localRef", "head", "ahead", "behind",
    ];
    value
        .as_object()
        .is_some_and(|o| o.len() == names.len() && names.iter().all(|n| o.contains_key(*n)))
        && value["state"] == "not-configured"
        && ["remote", "mergeRef", "localRef", "head", "ahead", "behind"]
            .into_iter()
            .all(|name| value[name].is_null())
}
pub(super) fn review(value: &push::Review, base: &str, target: &str) -> bool {
    value.valid()
        && value.action == push::Kind::PushNewBranch
        && value.remote.is_none()
        && value.tracking_ref.is_none()
        && value.basis == push::new_branch::BASIS
        && value.head == target
        && value.branch == "refs/heads/main"
        && value.upstream_ref == "refs/heads/main"
        && value.expected_remote_oid == push::new_branch::ZERO
        && value.commits == [base, target]
}
pub(super) fn refused_prepare(case: Case, value: &local::Projection, review_absent: bool) -> bool {
    case == Case::Equal
        && review_absent
        && value.phase == local::Phase::Prepare
        && value.stage == read::Phase::Settled
        && value.outcome == Some(read::Outcome::Refused)
        && value.reason.as_deref() == Some("target-changed")
        && value.result.is_null()
}
/// Called only after the parent matched its actual retired original ticket.
/// A pre-hook refusal can preserve private recovery paths. It is not a clean
/// Apply, and a synthetic server `ng` is not evidence of real server CAS.
pub(super) fn expected_apply(case: Case, value: &local::Projection) -> bool {
    let local::PublicAction::Push(action) = &value.action else {
        return false;
    };
    if action.kind != push::Kind::PushNewBranch
        || !action.valid()
        || value.phase != local::Phase::Apply
        || value.stage != read::Phase::Settled
        || (!value.result.is_null() && value.result["action"] != "push-new-branch")
        || (value.result["intent"].is_object()
            && (value.result["intent"]["action"] != "push-new-branch"
                || value.result["intent"]["oldOid"] != push::new_branch::ZERO
                || value.result["intent"]["newOid"] != action.new_oid))
    {
        return false;
    }
    match case {
        Case::Empty => super::expected_apply(super::Case::Pack, value),
        Case::Equal => false,
        Case::Stale => super::expected_apply(super::Case::Stale, value),
        Case::Held => super::expected_apply(super::Case::Held, value),
        Case::Race => {
            value.outcome == Some(read::Outcome::Ok)
                && value.reason.is_none()
                && value.result["state"] == "recovery-required"
                && value.result["settlement"] == "settled"
                && value.result["intent"].is_object()
                && value.result["effectPhase"] == "send-consumed"
                && value.result["reason"] == "remote-rejected"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn projection() -> local::Projection {
        let action = push::new_branch::tests::action();
        local::Projection {
            operation_id: "git-local-2".into(),
            context: read::Context {
                project_id: "project-1".into(),
                generation: 1,
                revision: "a".repeat(64),
            },
            phase: local::Phase::Apply,
            action: local::PublicAction::Push(action),
            stage: read::Phase::Settled,
            outcome: Some(read::Outcome::Ok),
            reason: None,
            result: json!({"action":"push-new-branch","state":"succeeded","settlement":"settled",
                "reason":null,"effectPhase":"remote-returned","retainedPaths":[],
                "intent":push::new_branch::tests::intent()}),
        }
    }
    #[test]
    fn create_case_kind_never_qualifies_an_ordinary_push_control() {
        for case in super::super::Case::ALL {
            assert_eq!(
                case.kind() == local::Kind::PushNewBranch,
                case.create().is_some()
            );
            assert_eq!(
                case.apply_requested(),
                case != super::super::Case::Create(Case::Equal)
            );
            // The actual Supervisor inspect branch uses is_push(), then the
            // same retained Gate/Control requires exact kind equality. This
            // table checks those DATA predicates, not native source custody.
            for kind in [
                local::Kind::Stage,
                local::Kind::Unstage,
                local::Kind::Commit,
                local::Kind::BranchCreate,
                local::Kind::BranchSwitch,
                local::Kind::BranchRename,
                local::Kind::FastForward,
                local::Kind::Fetch,
                local::Kind::Push,
                local::Kind::PushNewBranch,
                local::Kind::Initialize,
            ] {
                assert_eq!(
                    kind.is_push(),
                    matches!(kind, local::Kind::Push | local::Kind::PushNewBranch)
                );
                assert_eq!(
                    kind.is_push() && kind == case.kind(),
                    match kind {
                        local::Kind::Push => case.create().is_none(),
                        local::Kind::PushNewBranch => case.create().is_some(),
                        _ => false,
                    }
                );
            }
        }
        assert_eq!(super::super::NAMES.len(), 3);
        assert_eq!(NAMES.len(), 5);
        assert!(!tracking(&json!({"state":"gone"})));
        assert!(!tracking(&json!({"state":"not-configured"})));
        assert!(tracking(
            &json!({"state":"not-configured","remote":null,"mergeRef":null,
            "localRef":null,"head":null,"ahead":null,"behind":null})
        ));
        assert!(!tracking(
            &json!({"state":"not-configured","remote":"origin"})
        ));
    }
    #[test]
    fn prepare_only_requires_actual_refusal_without_review_or_apply_claim() {
        let mut p = projection();
        p.phase = local::Phase::Prepare;
        p.outcome = Some(read::Outcome::Refused);
        p.reason = Some("target-changed".into());
        p.result = Value::Null;
        assert!(refused_prepare(Case::Equal, &p, true));
        assert!(!refused_prepare(Case::Equal, &p, false));
        assert!(!refused_prepare(Case::Stale, &p, true));
        p.outcome = Some(read::Outcome::CleanupUnknown);
        assert!(!refused_prepare(Case::Equal, &p, true));
        p.outcome = Some(read::Outcome::Refused);
        p.phase = local::Phase::Apply;
        assert!(!refused_prepare(Case::Equal, &p, true));
    }
    #[test]
    fn create_review_keeps_both_reachable_commits_and_absent_upstream() {
        let mut r = push::new_branch::tests::review();
        let base = "1".repeat(40);
        let target = r.head.clone();
        r.commits = vec![base.clone(), target.clone()];
        assert!(review(&r, &base, &target));
        r.commits.remove(0);
        assert!(!review(&r, &base, &target));
        r.commits.insert(0, base.clone());
        r.remote = Some("origin".into());
        assert!(!review(&r, &base, &target));
        r.remote = None;
        r.tracking_ref = Some("refs/remotes/origin/main".into());
        assert!(!review(&r, &base, &target));
    }
    #[test]
    fn rejected_zero_precondition_is_not_success_or_pre_send_refusal() {
        let mut p = projection();
        assert!(expected_apply(Case::Empty, &p));
        assert!(!expected_apply(Case::Race, &p));
        p.result["state"] = json!("recovery-required");
        p.result["reason"] = json!("remote-rejected");
        p.result["effectPhase"] = json!("send-consumed");
        assert!(expected_apply(Case::Race, &p));
        assert!(!expected_apply(Case::Empty, &p));
        assert!(!expected_apply(Case::Stale, &p));
        p.result["intent"]["oldOid"] = json!("3".repeat(40));
        assert!(!expected_apply(Case::Race, &p));
        p.outcome = Some(read::Outcome::CleanupUnknown);
        assert!(!expected_apply(Case::Race, &p));
    }
    #[test]
    fn fresh_apply_refusal_keeps_recovery_paths_and_held_stop_is_not_returned() {
        let mut p = projection();
        p.result = json!({"action":"push-new-branch","state":"recovery-required","settlement":"settled",
            "reason":"target-changed","effectPhase":"not-sent","intent":null,
            "retainedPaths":["mrk-git-fixture/mrk-git-push-fixture"]});
        assert!(expected_apply(Case::Stale, &p));
        assert!(!expected_apply(Case::Equal, &p));
        p.outcome = Some(read::Outcome::Cancelled);
        p.reason = Some("authorization".into());
        p.result = Value::Null;
        assert!(expected_apply(Case::Held, &p));
        assert!(!expected_apply(Case::Empty, &p));
        p.stage = read::Phase::Stopping;
        assert!(!expected_apply(Case::Held, &p));
    }
}
