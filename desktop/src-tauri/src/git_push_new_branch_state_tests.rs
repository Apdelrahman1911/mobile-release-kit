//! Actual shared row codec/reservation transitions with inert DATA only. No
//! old row, fake result, or successful deserialization constructs NativeUse.
use super::*;
use crate::git_push_protocol::{new_branch::tests as data, tests as ordinary};
use serde_json::{json, Value};

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
        "first-push",
        &wire::Review::Push(data::review()),
    )
    .unwrap()
}
fn intent() -> wire::Intent {
    wire::Intent::Push(data::intent())
}
fn snapshot(state: &State) -> Snapshot {
    Snapshot {
        revision: Revision(12),
        bytes: state.bytes().unwrap(),
    }
}
fn raw(value: Value) -> Snapshot {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    Snapshot {
        revision: Revision(12),
        bytes,
    }
}

#[test]
fn schema_nine_is_only_minted_by_reserve_and_retains_all_prior_bytes() {
    for version in 1..=8 {
        let old = Row::preparing(
            &project(1),
            "old-stage",
            &wire::Review::Files(wire::FileReview {
                action: wire::Kind::Stage,
                expected_revision: "a".repeat(64),
                paths: vec!["README".into()],
                whole_index: false,
                head: Some("1".repeat(40)),
                branch: Some("refs/heads/main".into()),
                expected_index: "c".repeat(64),
                review_digest: "d".repeat(64),
            }),
        )
        .unwrap();
        let mut state = State {
            schema_version: version,
            protocol: PROTOCOL.into(),
            rows: vec![old],
        };
        let before = snapshot(&state);
        assert_eq!(
            State::decode(&before).unwrap().bytes().unwrap(),
            before.bytes
        );
        let old_bytes = serde_json::to_vec(&state.rows[0]).unwrap();
        state.reserve(row(2)).unwrap();
        assert_eq!(state.schema_version, 9);
        assert_eq!(serde_json::to_vec(&state.rows[0]).unwrap(), old_bytes);
        assert!(state.rows[1].push.is_none() && state.rows[1].push_new_branch.is_some());
        let after = snapshot(&state);
        assert_eq!(State::decode(&after).unwrap().bytes().unwrap(), after.bytes);
    }
    let mut state = State::empty();
    state
        .reserve(
            Row::preparing(
                &project(1),
                "old-push",
                &wire::Review::Push(ordinary::review()),
            )
            .unwrap(),
        )
        .unwrap();
    let old = serde_json::to_vec(&state.rows[0]).unwrap();
    assert!(!std::str::from_utf8(&old).unwrap().contains("pushNewBranch"));
    state.reserve(row(2)).unwrap();
    assert_eq!(serde_json::to_vec(&state.rows[0]).unwrap(), old);
    assert_eq!(state.schema_version, 9);
}

#[test]
fn mixed_kind_or_old_schema_never_adopts_first_publication() {
    let mut state = State::empty();
    state.reserve(row(1)).unwrap();
    let good: Value = serde_json::from_slice(&state.bytes().unwrap()).unwrap();
    for version in [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 255] {
        let mut changed = good.clone();
        changed["schemaVersion"] = json!(version);
        assert!(State::decode(&raw(changed)).is_err());
    }
    for (key, value) in [
        ("action", json!("push")),
        ("pushNewBranch", Value::Null),
        ("push", good["rows"][0]["pushNewBranch"].clone()),
        ("fetch", json!({})),
        ("expectedHead", json!("0".repeat(40))),
    ] {
        let mut changed = good.clone();
        changed["rows"][0][key] = value;
        assert!(State::decode(&raw(changed)).is_err());
    }
    let mut other = good;
    other["rows"][0]["pushNewBranch"]["reviewed"]["action"] = json!("push");
    assert!(State::decode(&raw(other)).is_err());
}

#[test]
fn candidate_is_one_use_exact_kind_and_uncertainty_blocks_both_push_families() {
    let original = row(1);
    let mut pending = original.clone();
    assert!(pending
        .candidate(&wire::Intent::Push(ordinary::intent()))
        .is_err());
    assert!(pending == original);
    pending.candidate(&intent()).unwrap();
    assert!(pending.same_original(&original) && pending.intent() == Some(intent()));
    let unchanged = pending.clone();
    assert!(pending.candidate(&intent()).is_err());
    assert!(pending == unchanged);
    assert!(pending.clone().finish(Completion::Cancelled).is_err());
    assert!(pending.clone().finish(Completion::Succeeded).is_err());
    pending.finish(Completion::RecoveryRequired).unwrap();
    let state = State {
        schema_version: 9,
        protocol: PROTOCOL.into(),
        rows: vec![pending],
    };
    let snapshot = snapshot(&state);
    let mut reopened = State::decode(&snapshot).unwrap();
    assert!(reopened.reserve(row(1)).is_err());
    assert!(reopened
        .reserve(
            Row::preparing(
                &project(1),
                "retry-old-push",
                &wire::Review::Push(ordinary::review())
            )
            .unwrap()
        )
        .is_err());
    assert_eq!(reopened.bytes().unwrap(), snapshot.bytes);
}

#[test]
fn known_remote_data_does_not_clear_retained_recovery_or_downgrade_schema() {
    let mut pending = row(1);
    pending.candidate(&intent()).unwrap();
    let returned = push::FinalData {
        effect_phase: crate::git_push_protocol::Effect::RemoteReturned,
        retained_paths: vec!["mrk-git-a/mrk-git-push-b".into()],
        transmission: wire::push_worker::tests::returned(),
    };
    assert!(pending
        .clone()
        .finish_with_push(
            Completion::Succeeded,
            None,
            None,
            None,
            None,
            Some(&returned)
        )
        .is_err());
    pending
        .finish_with_push(
            Completion::RecoveryRequired,
            None,
            None,
            None,
            None,
            Some(&returned),
        )
        .unwrap();
    assert!(!pending.replaceable());
    assert!(pending.clone().finish(Completion::Succeeded).is_err());
    let mut clean = row(1);
    clean.finish(Completion::Cancelled).unwrap();
    let mut state = State {
        schema_version: 9,
        protocol: PROTOCOL.into(),
        rows: vec![clean],
    };
    state
        .reserve(
            Row::preparing(
                &project(1),
                "old-push",
                &wire::Review::Push(ordinary::review()),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(state.schema_version, 9);
    assert!(state.rows[0].push.is_some() && state.rows[0].push_new_branch.is_none());
}
