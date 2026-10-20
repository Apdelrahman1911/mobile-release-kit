//! Same-row canonical DATA tests, not Store/NativeUse/ACK/finality receipts.
use super::*;
use crate::git_rename_protocol::tests as data;
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
        "rename-original",
        &wire::Review::Rename(data::review()),
    )
    .unwrap()
}
fn intent() -> wire::Intent {
    wire::Intent::Rename(data::intent())
}
fn snap(s: &State) -> Snapshot {
    Snapshot {
        revision: Revision(4),
        bytes: s.bytes().unwrap(),
    }
}
#[test]
fn only_explicit_rename_preparing_upgrades_v1_v2_v3_and_preserves_prior_rows() {
    let reviews = [
        wire::Review::Files(wire::FileReview {
            action: wire::Kind::Stage,
            expected_revision: "a".repeat(64),
            paths: vec!["a".into()],
            whole_index: false,
            head: Some("1".repeat(40)),
            branch: Some("refs/heads/main".into()),
            expected_index: "c".repeat(64),
            review_digest: "2".repeat(64),
        }),
        wire::Review::Branch(branch::Review {
            action: branch::Kind::Create,
            name: "other".into(),
            target_ref: "refs/heads/other".into(),
            expected_revision: "a".repeat(64),
            expected_reference_revision: "b".repeat(64),
            head: "1".repeat(40),
            branch: Some("refs/heads/main".into()),
            expected_index: "c".repeat(64),
            review_digest: "2".repeat(64),
        }),
        wire::Review::Switch(crate::git_switch_protocol::tests::review()),
    ];
    let mut s = State::empty();
    for (i, r) in reviews.iter().enumerate() {
        s.reserve(Row::preparing(&project(i as u8 + 1), "old-original", r).unwrap())
            .unwrap();
        assert_eq!(s.schema_version, i as u8 + 1);
        let before = snap(&s);
        assert_eq!(
            State::decode(&before).unwrap().bytes().unwrap(),
            before.bytes
        );
        assert!(!String::from_utf8(before.bytes)
            .unwrap()
            .contains("\"rename\""));
    }
    let prior = s.rows.clone();
    s.reserve(row(4)).unwrap();
    assert_eq!(s.schema_version, 4);
    assert!(s.rows[..3] == prior);
    let snapshot = snap(&s);
    assert_eq!(
        State::decode(&snapshot).unwrap().bytes().unwrap(),
        snapshot.bytes
    );
    let mut v: serde_json::Value = serde_json::from_slice(&snapshot.bytes).unwrap();
    v["schemaVersion"] = json!(3);
    assert_eq!(
        State::decode(&Snapshot {
            revision: snapshot.revision,
            bytes: data::raw(v)
        })
        .err()
        .unwrap()
        .code,
        Error::RecoveryRequired
    );
}
#[test]
fn candidate_binds_original_policy_hashes_and_cannot_be_replayed_or_relabelled() {
    let original = row(1);
    let mut next = original.clone();
    next.candidate(&intent()).unwrap();
    assert!(next.same_original(&original) && next.intent() == Some(intent()));
    assert!(next.candidate(&intent()).is_err());
    for (key, v) in [
        ("expectedRevision", json!("9".repeat(64))),
        ("expectedReferenceRevision", json!("9".repeat(64))),
        ("expectedRef", json!("refs/heads/foreign")),
        ("targetRef", json!("refs/heads/other")),
        ("originalConfig", json!("9".repeat(64))),
        ("originalLog", json!("9".repeat(64))),
        ("configMoved", json!(false)),
        ("expectedTargetAbsent", json!(false)),
    ] {
        let mut value = serde_json::to_value(intent()).unwrap();
        value[key] = v;
        let changed: wire::Intent = serde_json::from_value(value).unwrap();
        let mut unchanged = original.clone();
        assert!(unchanged.candidate(&changed).is_err());
        assert!(unchanged == original);
    }
    let mut forged = original.clone();
    forged.action = wire::Kind::BranchSwitch;
    assert!(forged.validate().is_err());
    forged = original.clone();
    forged.candidate_index = Some("8".repeat(64));
    assert!(forged.validate().is_err());
}
#[test]
fn partial_or_uncertain_rename_never_recycles_or_claims_no_effect_after_candidate() {
    for candidate in [false, true] {
        let mut retained = row(1);
        if candidate {
            retained.candidate(&intent()).unwrap();
        }
        retained.finish(Completion::RecoveryRequired).unwrap();
        let mut s = State {
            schema_version: 4,
            protocol: PROTOCOL.into(),
            rows: vec![retained],
        };
        let before = snap(&s);
        assert!(s.reserve(row(1)).is_err());
        assert_eq!(s.bytes().unwrap(), before.bytes);
    }
    let mut retained = row(1);
    retained.candidate(&intent()).unwrap();
    assert!(retained.clone().finish(Completion::Failed).is_err());
    assert!(retained.clone().finish(Completion::Cancelled).is_err());
    assert!(retained.clone().finish(Completion::Succeeded).is_err());
    let partial = rename::FinalData {
        effect_phase: "ref-returned".into(),
        retained_paths: vec![".git/mrk-git-fixture/index".into()],
    };
    assert!(retained
        .clone()
        .finish_with_details(Completion::Succeeded, None, Some(&partial))
        .is_err());
    retained
        .finish_with_details(Completion::RecoveryRequired, None, Some(&partial))
        .unwrap();
    assert!(!retained.replaceable());
}
#[test]
fn final_detail_is_finite_and_success_requires_exact_completed_metadata_not_merely_ref() {
    let mut retained = row(1);
    retained.candidate(&intent()).unwrap();
    for phase in ["ref-returned", "head-returned", "index-returned", "done"] {
        let detail = rename::FinalData {
            effect_phase: phase.into(),
            retained_paths: vec![],
        };
        assert!(retained
            .clone()
            .finish_with_details(Completion::Succeeded, None, Some(&detail))
            .is_err());
    }
    let detail = rename::FinalData {
        effect_phase: "config-returned".into(),
        retained_paths: vec![],
    };
    retained
        .finish_with_details(Completion::Succeeded, None, Some(&detail))
        .unwrap();
    assert!(retained.replaceable());
    assert!(retained
        .finish_with_details(Completion::Succeeded, None, Some(&detail))
        .is_err());
    let mut bad = row(1);
    bad.rename.as_mut().unwrap().final_state = Some(detail);
    assert!(bad.validate().is_err());
}
