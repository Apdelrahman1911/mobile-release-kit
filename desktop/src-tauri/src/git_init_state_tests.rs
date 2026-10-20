//! Journal DATA only. No NativeUse, original ACK, joined worker or init call.
use super::*;
use serde_json::json;

fn project(n: u8) -> ProjectBinding {
    ProjectBinding {
        project_id: crate::service_protocol::Id::parse(&format!("{n:032x}")).unwrap(),
        canonical_root: "/inert/project".into(),
        device: 1,
        inode: 2,
    }
}
fn review() -> wire::Review {
    wire::Review::Initialize(init::Review {
        action: init::Kind::Initialize,
        expected_revision: "a".repeat(64),
        initial_branch: "main".into(),
        object_format: "sha1".into(),
        review_digest: "b".repeat(64),
    })
}
fn row() -> Row {
    Row::preparing(&project(2), "original-init", &review()).unwrap()
}
fn intent() -> wire::Intent {
    use sha2::{Digest, Sha256};
    wire::Intent::Initialize(init::Intent {
        action: init::Kind::Initialize,
        expected_revision: "a".repeat(64),
        initial_branch: "main".into(),
        object_format: "sha1".into(),
        candidate_manifest: "c".repeat(64),
        candidate_head: Sha256::digest(b"ref: refs/heads/main\n")
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect(),
        candidate_config: "d".repeat(64),
    })
}
fn old_row() -> Row {
    Row::preparing(
        &project(1),
        "original-stage",
        &wire::Review::Files(wire::FileReview {
            action: wire::Kind::Stage,
            expected_revision: "a".repeat(64),
            paths: vec!["README".into()],
            whole_index: false,
            head: None,
            branch: Some("refs/heads/main".into()),
            expected_index: "c".repeat(64),
            review_digest: "b".repeat(64),
        }),
    )
    .unwrap()
}
fn bytes(value: serde_json::Value) -> Vec<u8> {
    let mut b = serde_json::to_vec(&value).unwrap();
    b.push(b'\n');
    b
}

#[test]
fn init_schema_seven_is_actual_reservation_only_and_old_rows_remain_canonical() {
    for version in 1..=6 {
        let mut state = State {
            schema_version: version,
            protocol: PROTOCOL.into(),
            rows: vec![old_row()],
        };
        let before = state.bytes().unwrap();
        let parsed = State::decode(&Snapshot {
            revision: Revision(3),
            bytes: before.clone(),
        })
        .unwrap();
        assert_eq!(parsed.bytes().unwrap(), before);
        let old = state.rows[0].clone();
        state.reserve(row()).unwrap();
        assert_eq!(state.schema_version, 7);
        assert!(state.rows[0] == old);
        let encoded: serde_json::Value = serde_json::from_slice(&state.bytes().unwrap()).unwrap();
        assert!(encoded["rows"][0]["expectedIndex"].is_string());
        assert!(!encoded["rows"][0]
            .as_object()
            .unwrap()
            .contains_key("initialization"));
        assert!(encoded["rows"][1]["expectedIndex"].is_null());
        assert!(
            encoded["rows"][1]["expectedRef"].is_null()
                && encoded["rows"][1]["expectedHead"].is_null()
        );
    }
    // Preserve the already-supported schema-five family as well as older file
    // rows. This is canonical journal DATA, not a fast-forward or init receipt.
    for version in 5..=6 {
        let previous = Row::preparing(
            &project(1),
            "original-fast-forward",
            &wire::Review::FastForward(crate::git_fast_forward_protocol::tests::review()),
        )
        .unwrap();
        let state = State {
            schema_version: version,
            protocol: PROTOCOL.into(),
            rows: vec![previous.clone()],
        };
        let before = state.bytes().unwrap();
        let mut parsed = State::decode(&Snapshot {
            revision: Revision(4),
            bytes: before.clone(),
        })
        .unwrap();
        assert_eq!(parsed.bytes().unwrap(), before);
        parsed.reserve(row()).unwrap();
        assert_eq!(parsed.schema_version, 7);
        assert!(parsed.rows[0] == previous);
    }
}

#[test]
fn init_rows_refuse_old_schema_invented_index_or_missing_null_without_reset() {
    let mut state = State::empty();
    state.reserve(row()).unwrap();
    let good: serde_json::Value = serde_json::from_slice(&state.bytes().unwrap()).unwrap();
    for version in 1..=6 {
        let mut changed = good.clone();
        changed["schemaVersion"] = json!(version);
        assert!(State::decode(&Snapshot {
            revision: Revision(1),
            bytes: bytes(changed)
        })
        .is_err());
    }
    for (key, value) in [
        ("expectedIndex", json!("f".repeat(64))),
        ("expectedRef", json!("refs/heads/main")),
        ("expectedHead", json!("1".repeat(40))),
        ("branch", json!({})),
        ("candidateIndex", json!("a".repeat(64))),
    ] {
        let mut changed = good.clone();
        changed["rows"][0][key] = value;
        assert!(State::decode(&Snapshot {
            revision: Revision(1),
            bytes: bytes(changed)
        })
        .is_err());
    }
    let mut missing = good;
    missing["rows"][0]
        .as_object_mut()
        .unwrap()
        .remove("expectedIndex");
    assert!(State::decode(&Snapshot {
        revision: Revision(1),
        bytes: bytes(missing)
    })
    .is_err());
}

#[test]
fn init_candidate_is_exact_once_and_negative_terminal_never_erases_possible_move() {
    let original = row();
    assert!(original.intent().is_none());
    let mut changed = intent();
    let wire::Intent::Initialize(i) = &mut changed else {
        panic!()
    };
    i.expected_revision = "f".repeat(64);
    assert!(original.clone().candidate(&changed).is_err());
    let mut pending = original.clone();
    pending.candidate(&intent()).unwrap();
    assert!(pending.same_original(&original) && pending.has_candidate());
    assert!(pending.candidate(&intent()).is_err());
    assert!(pending.clone().finish(Completion::Cancelled).is_err());
    assert!(pending.clone().finish(Completion::Failed).is_err());
    pending.finish(Completion::RecoveryRequired).unwrap();
    let mut state = State {
        schema_version: 7,
        protocol: PROTOCOL.into(),
        rows: vec![pending],
    };
    assert_eq!(
        state.reserve(row()).err().unwrap().code,
        Error::RecoveryRequired
    );
}
