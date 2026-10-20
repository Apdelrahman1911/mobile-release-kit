//! Real row/state codec, DATA only; no Store/NativeUse/native-finality witness.
use super::*;
use crate::git_fast_forward_protocol::tests as data;
use serde_json::json;
fn project(n: u8) -> ProjectBinding {
    ProjectBinding {
        project_id: crate::service_protocol::Id::parse(&format!("{n:032x}")).unwrap(),
        canonical_root: "/inert/project".into(),
        device: 1,
        inode: 2,
    }
}
fn row(n: u8) -> Row {
    Row::preparing(
        &project(n),
        "ff-original",
        &wire::Review::FastForward(data::review()),
    )
    .unwrap()
}
fn intent() -> wire::Intent {
    wire::Intent::FastForward(data::intent())
}
fn snapshot(s: &State) -> Snapshot {
    Snapshot {
        revision: Revision(4),
        bytes: s.bytes().unwrap(),
    }
}
#[test]
fn fast_forward_only_explicit_preparing_upgrades_old_state_and_preserves_rename_rows() {
    let old = Row::preparing(
        &project(1),
        "rename-original",
        &wire::Review::Rename(crate::git_rename_protocol::tests::review()),
    )
    .unwrap();
    let mut state = State {
        protocol: PROTOCOL.into(),
        schema_version: 4,
        rows: vec![old.clone()],
    };
    let before = snapshot(&state);
    assert_eq!(
        State::decode(&before).unwrap().bytes().unwrap(),
        before.bytes
    );
    assert!(!String::from_utf8(before.bytes)
        .unwrap()
        .contains("fastForward"));
    state.reserve(row(2)).unwrap();
    assert_eq!(state.schema_version, 5);
    assert!(state.rows[0] == old);
    let after = snapshot(&state);
    assert_eq!(State::decode(&after).unwrap().bytes().unwrap(), after.bytes);
    for version in [1, 2, 3, 4, 255] {
        let mut value: serde_json::Value = serde_json::from_slice(&after.bytes).unwrap();
        value["schemaVersion"] = json!(version);
        assert!(State::decode(&Snapshot {
            revision: after.revision,
            bytes: data::raw(value)
        })
        .is_err());
    }
}
#[test]
fn fast_forward_candidate_keeps_all_comparisons_and_cannot_switch_action_or_repeat() {
    let original = row(1);
    let mut changed = original.clone();
    changed.candidate(&intent()).unwrap();
    assert!(changed.same_original(&original) && changed.intent() == Some(intent()));
    assert!(changed.candidate(&intent()).is_err());
    for (field, value) in [
        ("targetRef", json!("refs/remotes/other/main")),
        ("targetOid", json!("7".repeat(40))),
        ("originalBranchLog", json!("7".repeat(64))),
        ("headLogEnabled", json!(false)),
        ("expectedReferenceRevision", json!("7".repeat(64))),
    ] {
        let mut v = serde_json::to_value(intent()).unwrap();
        v[field] = value;
        let bad: wire::Intent = serde_json::from_value(v).unwrap();
        let mut unchanged = original.clone();
        assert!(unchanged.candidate(&bad).is_err());
        assert!(unchanged == original);
    }
    let mut relabelled = changed;
    relabelled.action = wire::Kind::BranchSwitch;
    assert!(relabelled.validate().is_err());
}
#[test]
fn fast_forward_pending_and_partial_final_never_free_retry_or_report_no_effect() {
    for candidate in [false, true] {
        let mut r = row(1);
        if candidate {
            r.candidate(&intent()).unwrap();
        }
        r.finish(Completion::RecoveryRequired).unwrap();
        let mut state = State {
            protocol: PROTOCOL.into(),
            schema_version: 5,
            rows: vec![r],
        };
        let original = state.bytes().unwrap();
        assert!(state.reserve(row(1)).is_err());
        assert_eq!(state.bytes().unwrap(), original);
    }
    let mut r = row(1);
    r.candidate(&intent()).unwrap();
    assert!(r.clone().finish(Completion::Failed).is_err());
    assert!(r.clone().finish(Completion::Cancelled).is_err());
    assert!(r.clone().finish(Completion::Succeeded).is_err());
    let partial = ff::FinalData {
        effect_phase: "index-returned".into(),
        retained_paths: vec![".git/mrk-git-ff/index".into()],
    };
    assert!(r
        .clone()
        .finish_with_fast_forward(Completion::Succeeded, None, None, Some(&partial))
        .is_err());
    r.finish_with_fast_forward(Completion::RecoveryRequired, None, None, Some(&partial))
        .unwrap();
    assert!(!r.replaceable());
}
#[test]
fn fast_forward_known_success_requires_complete_ref_phase_not_checkout_or_index() {
    let mut r = row(1);
    r.candidate(&intent()).unwrap();
    for phase in [
        "not-published",
        "worktree-returned",
        "index-returned",
        "head-returned",
    ] {
        let d = ff::FinalData {
            effect_phase: phase.into(),
            retained_paths: vec![],
        };
        assert!(r
            .clone()
            .finish_with_fast_forward(Completion::Succeeded, None, None, Some(&d))
            .is_err());
    }
    let done = ff::FinalData {
        effect_phase: "ref-returned".into(),
        retained_paths: vec![],
    };
    r.finish_with_fast_forward(Completion::Succeeded, None, None, Some(&done))
        .unwrap();
    assert!(r.replaceable());
    let s = State {
        protocol: PROTOCOL.into(),
        schema_version: 5,
        rows: vec![r],
    };
    let saved = snapshot(&s);
    assert_eq!(State::decode(&saved).unwrap().bytes().unwrap(), saved.bytes);
}
