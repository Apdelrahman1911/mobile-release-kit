//! Same Store row codec over inert DATA. No Store/native use, joined witness,
//! filesystem, command, HTTP, publication or retry authority is constructed.
use super::*;
use crate::git_fetch_protocol::{self as protocol, tests as data};
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
        "fetch-original",
        &wire::Review::Fetch(data::review()),
    )
    .unwrap()
}
fn intent() -> wire::Intent {
    wire::Intent::Fetch(data::intent())
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
            branch: Some("refs/heads/local".into()),
            expected_index: "2".repeat(64),
            review_digest: "c".repeat(64),
        }),
    )
    .unwrap()
}
fn initialized(n: u8) -> Row {
    Row::preparing(
        &project(n),
        "old-initialization",
        &wire::Review::Initialize(init::Review {
            action: init::Kind::Initialize,
            expected_revision: "a".repeat(64),
            initial_branch: "main".into(),
            object_format: "sha1".into(),
            review_digest: "c".repeat(64),
        }),
    )
    .unwrap()
}

#[test]
fn fetch_explicit_reservation_upgrades_to_six_but_never_downgrades_init_seven() {
    for version in 1..=7 {
        let original = if version == 7 { initialized(1) } else { old(1) };
        let mut state = State {
            schema_version: version,
            protocol: PROTOCOL.into(),
            rows: vec![original.clone()],
        };
        let before = snapshot(&state);
        let parsed = State::decode(&before).unwrap();
        assert_eq!(parsed.bytes().unwrap(), before.bytes);
        assert!(!String::from_utf8(before.bytes)
            .unwrap()
            .contains("\"fetch\""));
        state.reserve(row(2)).unwrap();
        assert_eq!(state.schema_version, version.max(6));
        assert!(state.rows[0] == original);
        let after = snapshot(&state);
        assert_eq!(State::decode(&after).unwrap().bytes().unwrap(), after.bytes);
        if version == 7 {
            assert!(state.rows[0].initialization.is_some());
        }
    }
    let previous = Row::preparing(
        &project(1),
        "old-ff",
        &wire::Review::FastForward(crate::git_fast_forward_protocol::tests::review()),
    )
    .unwrap();
    let mut state = State {
        schema_version: 5,
        protocol: PROTOCOL.into(),
        rows: vec![previous.clone()],
    };
    state.reserve(row(2)).unwrap();
    assert!(state.rows[0] == previous);
}

#[test]
fn fetch_rows_refuse_wrong_schema_foreign_kind_and_erased_original_bindings() {
    let mut state = State::empty();
    state.reserve(row(1)).unwrap();
    let good: Value = serde_json::from_slice(&state.bytes().unwrap()).unwrap();
    for version in [0, 1, 2, 3, 4, 5, 10, 255] {
        let mut v = good.clone();
        v["schemaVersion"] = json!(version);
        assert!(State::decode(&Snapshot {
            revision: Revision(1),
            bytes: data::raw(v)
        })
        .is_err());
    }
    for (key, value) in [
        ("expectedIndex", Value::Null),
        ("expectedRef", json!("refs/heads/foreign")),
        ("reviewDigest", json!("f".repeat(64))),
        ("action", json!("stage")),
        ("fetch", Value::Null),
        ("initialization", json!({})),
    ] {
        let mut v = good.clone();
        v["rows"][0][key] = value;
        assert!(State::decode(&Snapshot {
            revision: Revision(1),
            bytes: data::raw(v)
        })
        .is_err());
    }
    let mut equal = data::review();
    equal.expected_target = Some(equal.candidate_ref_oid.clone());
    assert!(Row::preparing(&project(1), "same-tip", &wire::Review::Fetch(equal)).is_err());
}

#[test]
fn fetch_candidate_only_amends_same_review_and_preserves_original_on_refusal() {
    let original = row(1);
    let mut admitted = original.clone();
    admitted.candidate(&intent()).unwrap();
    assert!(admitted.same_original(&original) && admitted.intent() == Some(intent()));
    assert!(admitted.candidate_index.is_none() && admitted.candidate_commit.is_none());
    let retained = admitted.clone();
    assert!(admitted.candidate(&intent()).is_err());
    assert!(admitted == retained);
    for (key, value) in [
        ("reviewDigest", json!("f".repeat(64))),
        ("targetRef", json!("refs/remotes/origin/other")),
        ("expectedTarget", json!("8".repeat(40))),
        ("candidateRefOid", json!("8".repeat(40))),
        ("expectedReferenceRevision", json!("f".repeat(64))),
        ("expectedHead", json!("8".repeat(40))),
    ] {
        let mut v = serde_json::to_value(intent()).unwrap();
        v[key] = value;
        let bad: wire::Intent = serde_json::from_value(v).unwrap();
        let mut untouched = original.clone();
        assert!(untouched.candidate(&bad).is_err());
        assert!(untouched == original);
    }
}

#[test]
fn candidate_or_pending_cannot_be_relabelled_cancelled_or_reused_as_new_fetch() {
    for candidate in [false, true] {
        let mut r = row(1);
        if candidate {
            r.candidate(&intent()).unwrap();
        }
        let mut state = State {
            schema_version: 6,
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
        let before = state.bytes().unwrap();
        assert!(state.reserve(row(1)).is_err());
        assert_eq!(state.bytes().unwrap(), before);
    }
}

#[test]
fn success_requires_exact_final_phase_data_not_candidate_or_partial_pack_link() {
    let mut r = row(1);
    r.candidate(&intent()).unwrap();
    assert!(r.clone().finish(Completion::Succeeded).is_err());
    for phase in [
        protocol::Effect::NotPublished,
        protocol::Effect::PackLinked,
        protocol::Effect::ObjectsLinked,
        protocol::Effect::RefSendEntered,
    ] {
        let d = fetch::FinalData {
            effect_phase: phase,
            retained_paths: vec![],
        };
        assert!(r
            .clone()
            .finish_with_fetch(Completion::Succeeded, None, None, None, Some(&d))
            .is_err());
    }
    let partial = fetch::FinalData {
        effect_phase: protocol::Effect::PackLinked,
        retained_paths: vec![format!(
            "objects/pack/pack-{}.pack",
            data::intent().pack_oid
        )],
    };
    let mut stopped = r.clone();
    stopped
        .finish_with_fetch(
            Completion::RecoveryRequired,
            None,
            None,
            None,
            Some(&partial),
        )
        .unwrap();
    assert!(!stopped.replaceable());
    assert!(stopped.fetch.as_ref().unwrap().final_state.as_ref() == Some(&partial));
    let full = fetch::FinalData {
        effect_phase: protocol::Effect::RefPublished,
        retained_paths: vec![],
    };
    r.finish_with_fetch(Completion::Succeeded, None, None, None, Some(&full))
        .unwrap();
    assert!(r.replaceable());
    let mut state = State {
        schema_version: 7,
        protocol: PROTOCOL.into(),
        rows: vec![r],
    };
    // Explicit NEW reservation can reuse process-local text only after known
    // finished DATA. This test does not manufacture its required live Original.
    state.reserve(row(1)).unwrap();
    assert_eq!(state.schema_version, 7);
    assert!(state.rows[0].phase == Phase::Preparing);
}

#[test]
fn retained_recovery_paths_are_bounded_diagnostics_never_arbitrary_file_routes() {
    let i = data::intent();
    let d = fetch::FinalData {
        effect_phase: protocol::Effect::RefPublished,
        retained_paths: vec![format!("objects/pack/pack-{}.keep", i.pack_oid)],
    };
    assert!(d.valid(Some(&i)) && !d.successful(Some(&i)));
    for paths in [
        vec!["/tmp/foreign".into()],
        vec!["../foreign".into()],
        vec![format!("objects/pack/pack-{}.keep", "9".repeat(40))],
        vec!["mrk-git-fetch-a".into(); 2],
        (0..6).map(|n| format!("mrk-git-fetch-{n}")).collect(),
    ] {
        assert!(!fetch::FinalData {
            effect_phase: protocol::Effect::PackLinked,
            retained_paths: paths
        }
        .valid(Some(&i)));
    }
}

#[test]
fn bounded_row_cap_preserves_all_pending_projects_and_old_family_fields() {
    let mut state = State::empty();
    for n in 1..=MAX_ROWS as u8 {
        state.reserve(row(n)).unwrap();
    }
    let before = state.bytes().unwrap();
    assert!(before.len() <= STATE_LIMIT);
    assert!(state.reserve(row(MAX_ROWS as u8 + 1)).is_err());
    assert_eq!(state.bytes().unwrap(), before);
    let parsed = State::decode(&Snapshot {
        revision: Revision(1),
        bytes: before.clone(),
    })
    .unwrap();
    assert_eq!(parsed.bytes().unwrap(), before);
}
