//! DATA through the original GitLocal codecs; no FD, native ACK, admission or
//! finality witness is invented. Actual stock Git/macOS remain separate checks.
use super::*;
use crate::git_switch_protocol::tests as old;
use serde_json::{json, Value};

pub(crate) fn action() -> Action {
    Action {
        kind: Kind::FastForward,
        expected_revision: "a".repeat(64),
        expected_reference_revision: "c".repeat(64),
        target_ref: "refs/remotes/origin/main".into(),
        target_oid: "4".repeat(40),
    }
}
pub(crate) fn review() -> Review {
    let old = old::review();
    Review {
        action: Kind::FastForward,
        target_ref: action().target_ref,
        target_oid: action().target_oid,
        expected_revision: old.expected_revision,
        expected_reference_revision: old.expected_reference_revision,
        head: old.head,
        branch: old.branch,
        expected_index: old.expected_index,
        paths: old.paths,
        tracked_count: old.tracked_count,
        content_only: true,
        basis: "local-refs-no-fetch".into(),
        files: old.files,
        head_log: old.log.clone(),
        branch_log: old.log,
        review_digest: old.review_digest,
    }
}
pub(crate) fn intent() -> Intent {
    let r = review();
    Intent {
        action: Kind::FastForward,
        expected_revision: r.expected_revision,
        expected_reference_revision: r.expected_reference_revision,
        expected_ref: r.branch.clone(),
        expected_head: r.head,
        expected_index: r.expected_index,
        target_ref: r.target_ref,
        target_oid: r.target_oid,
        candidate_index: "d".repeat(64),
        original_head: shared::hash(format!("ref: {}\n", r.branch).as_bytes()),
        original_head_log: r.head_log.original_sha256,
        original_branch_log: r.branch_log.original_sha256,
        head_log_enabled: true,
        branch_log_enabled: true,
        footprint: "f".repeat(64),
    }
}
fn sources() -> Sources {
    let old = old::sources();
    Sources {
        target_lock: old.target_lock,
        head_log: old.head_log.clone(),
        branch_log: old.head_log,
        current_ref: NamedSnapshot {
            path: review().branch,
            snapshot: read::Snapshot {
                identity: (1, 13, 0o100644, 1001, 1001, 1, 41, 123, 456),
                sha256: shared::hash(format!("{}\n", review().head).as_bytes()),
            },
        },
        files: old.files,
    }
}
fn request(phase: local::Phase) -> local::Request {
    local::Request::from_fast_forward_original(
        "ff-fixture",
        &local::Action::FastForward(action()),
        &read::Context {
            project_id: "runtime-alias".into(),
            generation: 1,
            revision: "document-2".into(),
        },
        &old::native(),
        read::Clock {
            work_end_ns: 100_000_000_000,
            hard_end_ns: 110_000_000_000,
        },
        (phase == local::Phase::Apply).then(|| local::ApplyBinding {
            review: local::Review::FastForward(review()),
            journal_revision: 4,
        }),
        (phase == local::Phase::Apply).then(sources),
    )
    .unwrap()
}
pub(crate) fn raw(v: Value) -> Vec<u8> {
    old::raw(v)
}
fn candidate_value(r: &local::Request) -> Value {
    json!({"protocol":local::PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,"reviewDigest":review().review_digest,"intent":intent()})
}
fn terminal(r: &local::Request) -> Value {
    json!({"protocol":local::PROTOCOL,"kind":"terminal","id":r.id,"digest":r.digest,"phase":r.phase,"action":"fast-forward",
        "status":"ok","reason":null,"result":null,"publication":"not-reported","firstFailureNs":null,"cleanupEndNs":r.clock.hard_end_ns})
}
fn applied(r: &local::Request) -> Value {
    let mut v = terminal(r);
    v["publication"] = json!("ff-ref-returned");
    v["result"] = json!({"operationId":r.id,"action":"fast-forward","state":"succeeded","settlement":"settled","reason":null,
        "observation":{"revision":"e".repeat(64),"head":review().target_oid,"branch":review().branch,"unborn":false,"detached":false,
            "changes":[],"remotes":[],"restrictions":[]},"intent":intent(),"effectPhase":"ref-returned","retainedPaths":[]});
    v
}
#[test]
fn fixed_cached_tracking_action_has_no_fetch_force_or_caller_command_controls() {
    let v = json!({"projectId":"runtime-alias","expectedDocumentRevision":2,"action":action()});
    let local::Command::Prepare(p) =
        local::decode_command("git_local_prepare", &raw(v.clone())).unwrap()
    else {
        panic!()
    };
    assert!(p.action.kind() == local::Kind::FastForward && p.action.valid());
    assert_eq!(
        serde_json::to_value(p.action.public()).unwrap(),
        json!(action())
    );
    for field in [
        "paths", "message", "identity", "fetch", "force", "name", "argv",
    ] {
        let mut bad = v.clone();
        bad["action"][field] = Value::Null;
        assert!(local::decode_command("git_local_prepare", &raw(bad)).is_err());
    }
    for target in [
        "refs/heads/main",
        "refs/remotes/origin/HEAD",
        "refs/remotes/main",
        "refs/remotes/x/a.lock",
        "refs/remotes/x/../a",
    ] {
        let mut bad = v.clone();
        bad["action"]["targetRef"] = json!(target);
        assert!(local::decode_command("git_local_prepare", &raw(bad)).is_err());
    }
    let mut bad = v;
    bad["action"]
        .as_object_mut()
        .unwrap()
        .remove("expectedReferenceRevision");
    assert!(local::decode_command("git_local_prepare", &raw(bad)).is_err());
}
#[test]
fn prepare_review_binds_exact_old_head_branch_cached_target_and_content_scope() {
    let r = request(local::Phase::Prepare);
    let mut v = terminal(&r);
    v["result"] = json!({"review":review()});
    assert!(
        r.terminal(&raw(v.clone()), None).unwrap().review().unwrap()
            == local::Review::FastForward(review())
    );
    for (key, value) in [
        ("targetOid", json!(review().head)),
        ("targetRef", json!("refs/remotes/other/main")),
        ("basis", json!("remote-current")),
        ("contentOnly", json!(false)),
        ("expectedReferenceRevision", json!("0".repeat(64))),
        ("trackedCount", json!(257)),
        ("paths", json!([])),
    ] {
        let mut bad = v.clone();
        bad["result"]["review"][key] = value;
        assert!(r.terminal(&raw(bad), None).is_err());
    }
    // An ancestor with an identical tree is still a ref update, not a no-op.
    let mut same_tree = review();
    same_tree.paths.clear();
    same_tree.files.clear();
    assert!(same_tree.valid());
    v["result"] = json!({"review":same_tree});
    assert!(r.terminal(&raw(v), None).is_ok());
}
#[test]
fn native_sources_bind_both_logs_current_ref_and_same_tracking_lock_before_apply() {
    let r = request(local::Phase::Apply);
    let value: Value = serde_json::from_slice(r.bytes()).unwrap();
    assert_eq!(value["fastForward"], json!(sources()));
    assert!(value.get("switch").is_none());
    assert!(local::Request::from_original(
        &r.id,
        &r.action,
        &r.context,
        &r.native,
        r.clock,
        Some(local::ApplyBinding {
            review: local::Review::FastForward(review()),
            journal_revision: 4
        })
    )
    .is_err());
    let mut bad = sources();
    bad.current_ref.path = "refs/heads/other".into();
    assert!(!bad.valid(&old::native(), &review()));
    bad = sources();
    bad.current_ref.snapshot.sha256 = "0".repeat(64);
    assert!(!bad.valid(&old::native(), &review()));
    bad = sources();
    bad.branch_log = None;
    assert!(!bad.valid(&old::native(), &review()));
    bad = sources();
    bad.target_lock.parent_locked.1 += 1;
    assert!(!bad.valid(&old::native(), &review()));
    let mut absent = review();
    absent.branch_log = Log {
        enabled: false,
        original_kind: "absent".into(),
        original_sha256: shared::hash(b"absent"),
    };
    bad = sources();
    bad.branch_log = None;
    assert!(bad.valid(&old::native(), &absent));
}
#[test]
fn candidate_and_ack_bind_exact_prepared_originals_and_one_journal_revision() {
    let r = request(local::Phase::Apply);
    let v = candidate_value(&r);
    let c = r.candidate(&raw(v.clone())).unwrap();
    r.ack(&c, 5).unwrap();
    assert!(r.ack(&c, 4).is_err() && r.ack(&c, 6).is_err());
    for (field, value) in [
        ("targetOid", json!("7".repeat(40))),
        ("expectedRef", json!("refs/heads/other")),
        ("expectedIndex", json!("7".repeat(64))),
        ("originalHead", json!("7".repeat(64))),
        ("originalBranchLog", json!("7".repeat(64))),
        ("headLogEnabled", json!(false)),
        ("candidateHead", Value::Null),
    ] {
        let mut bad = v.clone();
        bad["intent"][field] = value;
        assert!(r.candidate(&raw(bad)).is_err());
    }
}
#[test]
fn success_requires_ref_returned_and_unchanged_symbolic_branch_not_just_checkout_or_index() {
    let r = request(local::Phase::Apply);
    let c = r.candidate(&raw(candidate_value(&r))).unwrap();
    let v = applied(&r);
    assert!(r
        .terminal(&raw(v.clone()), Some(&c))
        .unwrap()
        .child_declared_settled());
    assert!(r.terminal(&raw(v.clone()), None).is_err());
    for (marker, phase) in [
        ("not-reported", "not-published"),
        ("ff-worktree-returned", "worktree-returned"),
        ("ff-index-returned", "index-returned"),
        ("switch-index-returned", "index-returned"),
    ] {
        let mut bad = v.clone();
        bad["publication"] = json!(marker);
        bad["result"]["effectPhase"] = json!(phase);
        assert!(r.terminal(&raw(bad), Some(&c)).is_err());
    }
    for (field, value) in [
        ("head", json!(review().head)),
        ("branch", json!(review().target_ref)),
    ] {
        let mut bad = v.clone();
        bad["result"]["observation"][field] = value;
        assert!(r.terminal(&raw(bad), Some(&c)).is_err());
    }
    let mut bad = v;
    bad["result"]["retainedPaths"] = json!([".git/mrk-git-ff/index"]);
    assert!(r.terminal(&raw(bad), Some(&c)).is_err());
}
#[test]
fn partial_publication_keeps_bounded_recovery_not_rollback_or_replay() {
    let r = request(local::Phase::Apply);
    let c = r.candidate(&raw(candidate_value(&r))).unwrap();
    for (marker, phase) in [
        ("not-reported", "not-published"),
        ("ff-worktree-returned", "worktree-returned"),
        ("ff-index-returned", "index-returned"),
        ("ff-ref-returned", "ref-returned"),
    ] {
        let mut v = applied(&r);
        v["publication"] = json!(marker);
        v["firstFailureNs"] = json!(99_000_000_000u64);
        v["cleanupEndNs"] = json!(109_000_000_000u64);
        v["result"]["state"] = json!("recovery-required");
        v["result"]["reason"] = json!("recovery-required");
        v["result"]["observation"] = Value::Null;
        v["result"]["effectPhase"] = json!(phase);
        v["result"]["retainedPaths"] = json!([".git/mrk-git-ff/index"]);
        assert!(r.terminal(&raw(v.clone()), Some(&c)).is_ok());
        v["result"]["state"] = json!("failed");
        assert!(r.terminal(&raw(v), Some(&c)).is_err());
    }
    assert!(!retained_path(".git/mrk-git-ff/HEAD"));
    assert!(!retained_path(".git/mrk-git-ff/../../config"));
}
#[test]
fn final_data_is_not_a_join_receipt_and_must_match_actual_returned_marker() {
    let r = request(local::Phase::Apply);
    let c = r.candidate(&raw(candidate_value(&r))).unwrap();
    let t = r.terminal(&raw(applied(&r)), Some(&c)).unwrap();
    assert!(
        FinalData::from_returned(&r, &c, &t, local::Publication::FfRefReturned)
            .unwrap()
            .successful()
    );
    assert!(FinalData::from_returned(&r, &c, &t, local::Publication::FfIndexReturned).is_err());
    assert!(FinalData::from_returned(&r, &c, &t, local::Publication::NotReported).is_err());
    let mut bad = applied(&r);
    bad["result"]["effectPhase"] = Value::Null;
    assert!(r.terminal(&raw(bad), Some(&c)).is_err());
}
