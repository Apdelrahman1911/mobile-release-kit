//! The real shared row codec with inert DATA, not a synthetic NativeJoined,
//! live Store, source/provider grant or proof of a remote update.
use super::*;
use crate::git_push_protocol::tests as data;
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
        "push-original",
        &wire::Review::Push(data::review()),
    )
    .unwrap()
}
fn intent() -> wire::Intent {
    wire::Intent::Push(data::intent())
}
fn snapshot(state: &State) -> Snapshot {
    Snapshot {
        revision: Revision(9),
        bytes: state.bytes().unwrap(),
    }
}
fn old(n: u8) -> Row {
    Row::preparing(
        &project(n),
        "old-stage",
        &wire::Review::Files(wire::FileReview {
            action: wire::Kind::Stage,
            expected_revision: "a".repeat(64),
            paths: vec!["README".into()],
            whole_index: false,
            head: Some("1".repeat(40)),
            branch: Some("refs/heads/main".into()),
            expected_index: "2".repeat(64),
            review_digest: "c".repeat(64),
        }),
    )
    .unwrap()
}
fn full() -> push::FinalData {
    push::FinalData {
        effect_phase: crate::git_push_protocol::Effect::RemoteReturned,
        retained_paths: vec![],
        transmission: wire::push_worker::tests::returned(),
    }
}
fn raw(value: Value) -> Snapshot {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    Snapshot {
        revision: Revision(1),
        bytes,
    }
}

#[test]
fn push_first_preparing_cas_uses_schema_eight_and_keeps_exact_old_rows() {
    for version in 1..=7 {
        let original = old(1);
        let mut state = State {
            schema_version: version,
            protocol: PROTOCOL.into(),
            rows: vec![original.clone()],
        };
        let before = snapshot(&state);
        assert_eq!(
            State::decode(&before).unwrap().bytes().unwrap(),
            before.bytes
        );
        state.reserve(row(2)).unwrap();
        assert_eq!(state.schema_version, 8);
        assert!(state.rows[0] == original);
        let after = snapshot(&state);
        assert_eq!(State::decode(&after).unwrap().bytes().unwrap(), after.bytes);
    }
    let prior = [
        wire::Review::FastForward(crate::git_fast_forward_protocol::tests::review()),
        wire::Review::Fetch(crate::git_fetch_protocol::tests::review()),
        wire::Review::Initialize(init::Review {
            action: init::Kind::Initialize,
            expected_revision: "a".repeat(64),
            initial_branch: "main".into(),
            object_format: "sha1".into(),
            review_digest: "c".repeat(64),
        }),
    ];
    let mut state = State::empty();
    for (index, review) in prior.iter().enumerate() {
        state
            .reserve(Row::preparing(&project(index as u8 + 1), "prior", review).unwrap())
            .unwrap();
    }
    let before: Vec<_> = state
        .rows
        .iter()
        .map(|r| serde_json::to_vec(r).unwrap())
        .collect();
    state.reserve(row(4)).unwrap();
    for (index, bytes) in before.iter().enumerate() {
        assert_eq!(&serde_json::to_vec(&state.rows[index]).unwrap(), bytes);
    }
}

#[test]
fn wrong_schema_or_mixed_old_fields_never_become_an_empty_or_adopted_push() {
    let mut state = State::empty();
    state.reserve(row(1)).unwrap();
    let good: Value = serde_json::from_slice(&state.bytes().unwrap()).unwrap();
    for version in [0, 1, 2, 3, 4, 5, 6, 7, 10, 255] {
        let mut v = good.clone();
        v["schemaVersion"] = json!(version);
        assert!(State::decode(&raw(v)).is_err());
    }
    for (key, value) in [
        ("expectedIndex", Value::Null),
        ("expectedRef", json!("refs/heads/foreign")),
        ("expectedHead", json!("3".repeat(40))),
        ("reviewDigest", json!("f".repeat(64))),
        ("action", json!("fetch")),
        ("push", Value::Null),
        ("fetch", json!({})),
        ("initialization", json!({})),
    ] {
        let mut v = good.clone();
        v["rows"][0][key] = value;
        assert!(State::decode(&raw(v)).is_err());
    }
}

#[test]
fn candidate_amends_only_same_account_refs_and_review_without_erasing_original() {
    let original = row(1);
    let mut admitted = original.clone();
    admitted.candidate(&intent()).unwrap();
    assert!(admitted.same_original(&original));
    assert!(admitted.intent() == Some(intent()));
    let retained = admitted.clone();
    assert!(admitted.candidate(&intent()).is_err());
    assert!(admitted == retained);
    for (key, value) in [
        ("accountId", json!("99")),
        ("repositoryId", json!("99")),
        ("oldOid", json!("3".repeat(40))),
        ("newOid", json!("4".repeat(40))),
        ("localRef", json!("refs/heads/other")),
        ("remoteRef", json!("refs/heads/other")),
        ("reviewDigest", json!("f".repeat(64))),
        ("commitsSha256", json!("f".repeat(64))),
    ] {
        let mut v = serde_json::to_value(intent()).unwrap();
        v[key] = value;
        let proposed: wire::Intent = serde_json::from_value(v).unwrap();
        let mut same = original.clone();
        assert!(same.candidate(&proposed).is_err());
        assert!(same == original);
    }
}

#[test]
fn pending_or_acknowledged_unknown_stays_fenced_after_restart_without_retry() {
    for candidate in [false, true] {
        let mut r = row(1);
        if candidate {
            r.candidate(&intent()).unwrap();
        }
        let mut state = State {
            schema_version: 8,
            protocol: PROTOCOL.into(),
            rows: vec![r.clone()],
        };
        let before = state.bytes().unwrap();
        assert!(state.reserve(row(1)).is_err());
        assert_eq!(state.bytes().unwrap(), before);
        if candidate {
            assert!(r.clone().finish(Completion::Cancelled).is_err());
            assert!(r.clone().finish(Completion::Failed).is_err());
        }
        r.finish(Completion::RecoveryRequired).unwrap();
        state.rows[0] = r;
        let snapshot = snapshot(&state);
        let mut reopened = State::decode(&snapshot).unwrap();
        assert!(reopened.reserve(row(1)).is_err());
        assert_eq!(reopened.bytes().unwrap(), snapshot.bytes);
    }
}

#[test]
fn remote_receipt_data_does_not_supply_native_finality_or_turn_recovery_into_success() {
    let mut r = row(1);
    r.candidate(&intent()).unwrap();
    assert!(r.clone().finish(Completion::Succeeded).is_err());
    let mut incomplete = full();
    incomplete.effect_phase = crate::git_push_protocol::Effect::SendEntered;
    assert!(r
        .clone()
        .finish_with_push(
            Completion::Succeeded,
            None,
            None,
            None,
            None,
            Some(&incomplete)
        )
        .is_err());
    let mut retained = full();
    retained.retained_paths = vec!["mrk-git-push-original".into()];
    assert!(r
        .clone()
        .finish_with_push(
            Completion::Succeeded,
            None,
            None,
            None,
            None,
            Some(&retained)
        )
        .is_err());
    let mut stopped = r.clone();
    stopped
        .finish_with_push(
            Completion::RecoveryRequired,
            None,
            None,
            None,
            None,
            Some(&retained),
        )
        .unwrap();
    assert!(!stopped.replaceable());
    assert!(stopped.clone().finish(Completion::Succeeded).is_err());
    r.finish_with_push(Completion::Succeeded, None, None, None, None, Some(&full()))
        .unwrap();
    assert!(r.replaceable());
    let mut state = State {
        schema_version: 8,
        protocol: PROTOCOL.into(),
        rows: vec![r],
    };
    state.reserve(old(1)).unwrap();
    assert_eq!(state.schema_version, 8); // Never downgrade after a later local action.
}

#[test]
fn shared_row_limit_refuses_new_project_without_evicting_any_unknown() {
    let mut state = State::empty();
    for n in 1..=MAX_ROWS as u8 {
        state.reserve(row(n)).unwrap();
    }
    let before = state.bytes().unwrap();
    assert!(state.reserve(row(MAX_ROWS as u8 + 1)).is_err());
    assert_eq!(state.bytes().unwrap(), before);
    assert_eq!(
        State::decode(&snapshot(&state)).unwrap().bytes().unwrap(),
        before
    );
}
