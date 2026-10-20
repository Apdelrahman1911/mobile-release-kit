//! Real closed codecs with synthetic DATA, never native/source/join authority.
use super::*;
use serde_json::{json, Value};

pub(crate) fn action() -> Action {
    Action {
        kind: Kind::Rename,
        name: "next".into(),
        expected_revision: "a".repeat(64),
        expected_reference_revision: "b".repeat(64),
    }
}
pub(crate) fn review() -> Review {
    Review {
        action: Kind::Rename,
        name: "next".into(),
        target_ref: "refs/heads/next".into(),
        expected_revision: "a".repeat(64),
        expected_reference_revision: "b".repeat(64),
        head: "1".repeat(40),
        branch: "refs/heads/main".into(),
        expected_index: "c".repeat(64),
        config_moved: true,
        logging: true,
        original_config: "d".repeat(64),
        original_log: "e".repeat(64),
        original_head_log: "f".repeat(64),
        review_digest: "2".repeat(64),
    }
}
pub(crate) fn intent() -> Intent {
    let r = review();
    Intent {
        action: Kind::Rename,
        expected_revision: r.expected_revision,
        expected_reference_revision: r.expected_reference_revision,
        expected_ref: r.branch,
        expected_head: r.head,
        expected_index: r.expected_index,
        target_ref: r.target_ref,
        expected_target_absent: true,
        original_config: r.original_config,
        candidate_config: "3".repeat(64),
        original_log: r.original_log,
        candidate_log: "4".repeat(64),
        original_head_log: r.original_head_log,
        candidate_head_log: "5".repeat(64),
        config_moved: true,
        logging: true,
    }
}
fn native() -> read::Native {
    let r = review();
    let file = |n, size, sha| read::Snapshot {
        identity: (1, n, 0o100600, 1001, 1001, 1, size, 123, 456),
        sha256: sha,
    };
    read::Native {
        uid: 1001,
        gid: 1001,
        root: "/inert/project".into(),
        directories: read::Directories {
            root: (1, 2, 0o40700, 1001, 1001),
            git: (1, 3, 0o40700, 1001, 1001),
            objects: (1, 4, 0o40700, 1001, 1001),
        },
        tool: read::Snapshot {
            identity: (1, 5, 0o100755, 0, 0, 1, 12, 123, 456),
            sha256: "6".repeat(64),
        },
        files: read::Files {
            head: file(6, 21, hash(format!("ref: {}\n", r.branch).as_bytes())),
            config: file(7, 100, r.original_config),
            index: Some(file(8, 12, r.expected_index)),
        },
    }
}
fn sources() -> Sources {
    Sources {
        source_ref: review().branch,
        ref_locks: RefLocks {
            source_identity: (1, 9, 0o100600, 1001, 1001, 1, 0, 123, 456),
            target_identity: (1, 10, 0o100600, 1001, 1001, 1, 0, 123, 456),
            parent_before: (1, 11, 0o40700, 1001, 1001, 2, 4096, 100, 100),
            parent_locked: (1, 11, 0o40700, 1001, 1001, 2, 4096, 200, 200),
        },
        reference: read::Snapshot {
            identity: (1, 12, 0o100600, 1001, 1001, 1, 41, 123, 456),
            sha256: hash(format!("{}\n", review().head).as_bytes()),
        },
        branch_log: Some(read::Snapshot {
            identity: (1, 13, 0o100600, 1001, 1001, 1, 12, 123, 456),
            sha256: review().original_log,
        }),
        head_log: Some(read::Snapshot {
            identity: (1, 14, 0o100600, 1001, 1001, 1, 12, 123, 456),
            sha256: review().original_head_log,
        }),
    }
}
fn request(phase: local::Phase) -> local::Request {
    local::Request::from_rename_original(
        "rename-original",
        &local::Action::Rename(action()),
        &read::Context {
            project_id: "project-fixture".into(),
            generation: 1,
            revision: "document-2".into(),
        },
        &native(),
        read::Clock {
            work_end_ns: 100_000_000_000,
            hard_end_ns: 110_000_000_000,
        },
        (phase == local::Phase::Apply).then(|| local::ApplyBinding {
            review: local::Review::Rename(review()),
            journal_revision: 4,
        }),
        (phase == local::Phase::Apply).then(sources),
    )
    .unwrap()
}
pub(crate) fn raw(v: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&v).unwrap();
    bytes.push(b'\n');
    bytes
}
fn candidate(r: &local::Request) -> local::Candidate {
    r.candidate(&raw(
        json!({"protocol":local::PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,
    "reviewDigest":review().review_digest,"intent":intent()}),
    ))
    .unwrap()
}
fn terminal(r: &local::Request) -> Value {
    json!({"protocol":local::PROTOCOL,"kind":"terminal","id":r.id,"digest":r.digest,"phase":r.phase,
    "action":"branch-rename","status":"ok","reason":null,"result":null,"publication":"not-reported","firstFailureNs":null,"cleanupEndNs":r.clock.hard_end_ns})
}
fn applied(r: &local::Request) -> Value {
    let mut v = terminal(r);
    v["publication"] = json!("rename-config-returned");
    v["result"] = json!({"operationId":r.id,"action":"branch-rename","state":"succeeded","settlement":"settled","reason":null,
        "observation":{"revision":"7".repeat(64),"head":review().head,"branch":review().target_ref,"unborn":false,"detached":false,
            "changes":[],"remotes":[],"restrictions":[]},"intent":intent(),"effectPhase":"config-returned","retainedPaths":[]});
    v
}

#[test]
fn rename_command_adds_only_name_and_two_current_revisions() {
    let value =
        json!({"projectId":"project-fixture","expectedDocumentRevision":2,"action":action()});
    let local::Command::Prepare(p) =
        local::decode_command("git_local_prepare", &raw(value.clone())).unwrap()
    else {
        panic!()
    };
    assert!(p.action.kind() == local::Kind::BranchRename && p.action.valid());
    for key in [
        "paths",
        "force",
        "identity",
        "message",
        "oldName",
        "targetOid",
        "rename",
        "argv",
        "review",
        "root",
    ] {
        let mut bad = value.clone();
        bad["action"][key] = Value::Null;
        assert!(local::decode_command("git_local_prepare", &raw(bad)).is_err());
    }
    for key in ["name", "expectedRevision", "expectedReferenceRevision"] {
        let mut bad = value.clone();
        bad["action"].as_object_mut().unwrap().remove(key);
        assert!(local::decode_command("git_local_prepare", &raw(bad)).is_err());
    }
    for name in ["-f", "@{-1}", "a..b", "a.lock", "a//b", "", "é"] {
        let mut bad = value.clone();
        bad["action"]["name"] = json!(name);
        assert!(local::decode_command("git_local_prepare", &raw(bad)).is_err());
    }
    assert!(local::Action::index(
        local::Kind::BranchRename,
        "a".repeat(64),
        vec!["file".into()]
    )
    .is_err());
}

#[test]
fn rename_review_requires_exact_parent_old_index_and_log_policy_without_private_config() {
    let r = request(local::Phase::Prepare);
    let mut value = terminal(&r);
    value["result"] = json!({"review":review()});
    assert!(
        r.terminal(&raw(value.clone()), None)
            .unwrap()
            .review()
            .unwrap()
            == local::Review::Rename(review())
    );
    for (key, data) in [
        ("branch", json!("refs/heads/dir/main")),
        ("targetRef", json!("refs/heads/MAIN")),
        ("expectedReferenceRevision", json!("0".repeat(64))),
        ("expectedIndex", Value::Null),
        ("logging", json!(false)),
        ("config", json!("private")),
    ] {
        let mut bad = value.clone();
        bad["result"]["review"][key] = data;
        assert!(r.terminal(&raw(bad), None).is_err());
    }
    let mut no_logs = review();
    no_logs.logging = false;
    no_logs.original_log = hash(b"absent");
    no_logs.original_head_log = hash(b"absent");
    assert!(no_logs.valid());
    value["result"] = json!({"review":no_logs});
    assert!(r.terminal(&raw(value.clone()), None).is_ok());
    value["result"]["diff"] = Value::Null;
    assert!(r.terminal(&raw(value), None).is_err());
}

#[test]
fn rename_apply_requires_two_distinct_empty_original_locks_and_complete_snapshot() {
    let r = request(local::Phase::Apply);
    let value: Value = serde_json::from_slice(r.bytes()).unwrap();
    assert_eq!(value["rename"], json!(sources()));
    let prepare = request(local::Phase::Prepare);
    let value: Value = serde_json::from_slice(prepare.bytes()).unwrap();
    assert!(value["rename"].is_null());
    assert!(local::Request::from_original(
        &r.id,
        &r.action,
        &r.context,
        &r.native,
        r.clock,
        Some(local::ApplyBinding {
            review: local::Review::Rename(review()),
            journal_revision: 4
        })
    )
    .is_err());
    for change in [
        (|s: &mut Sources| s.ref_locks.target_identity = s.ref_locks.source_identity)
            as fn(&mut Sources),
        |s| s.ref_locks.source_identity.6 = 1,
        |s| s.ref_locks.parent_locked.1 += 1,
        |s| s.head_log = None,
        |s| s.reference.identity.5 = 2,
        |s| s.reference.sha256 = "0".repeat(64),
    ] {
        let mut s = sources();
        change(&mut s);
        assert!(!s.valid(&native(), &review()));
    }
    let mut n = native();
    n.files.index.as_mut().unwrap().identity.6 = INDEX_LIMIT + 1;
    assert!(!sources().valid(&n, &review()));
    let c = candidate(&r);
    assert!(r.ack(&c, 5).is_ok());
    assert!(r.ack(&c, 4).is_err());
}

#[test]
fn rename_terminal_success_requires_last_real_phase_and_unchanged_commit() {
    let r = request(local::Phase::Apply);
    let c = candidate(&r);
    let value = applied(&r);
    assert!(r.terminal(&raw(value.clone()), Some(&c)).is_ok());
    for change in [
        (|v: &mut Value| v["publication"] = json!("rename-ref-returned")) as fn(&mut Value),
        |v| v["result"]["observation"]["head"] = json!("9".repeat(40)),
        |v| v["result"]["observation"]["branch"] = json!("refs/heads/main"),
        |v| v["result"]["retainedPaths"] = json!([".git/mrk-git-fixture/index"]),
        |v| v["firstFailureNs"] = json!(100_000_000_000u64),
    ] {
        let mut bad = value.clone();
        change(&mut bad);
        assert!(r.terminal(&raw(bad), Some(&c)).is_err());
    }
    let mut partial = value;
    partial["publication"] = json!("rename-ref-returned");
    partial["firstFailureNs"] = json!(100_000_000_000u64);
    partial["result"]["state"] = json!("recovery-required");
    partial["result"]["reason"] = json!("recovery-required");
    partial["result"]["observation"] = Value::Null;
    partial["result"]["effectPhase"] = json!("ref-returned");
    partial["result"]["retainedPaths"] = json!([".git/mrk-git-fixture/index"]);
    assert!(r.terminal(&raw(partial.clone()), Some(&c)).is_ok());
    partial["result"]["state"] = json!("failed");
    assert!(r.terminal(&raw(partial), Some(&c)).is_err());
}

#[test]
fn moved_reference_is_same_inode_nlink_one_not_replacement_or_global_refresh() {
    let original = sources().reference.identity;
    let mut after = original;
    after.8 += 1;
    assert!(moved_original(original, after));
    for bad in [
        (
            original.0, 999, original.2, original.3, original.4, 1, original.6, original.7,
            original.8,
        ),
        (
            original.0, original.1, original.2, original.3, original.4, 0, original.6, original.7,
            original.8,
        ),
        (
            original.0,
            original.1,
            original.2,
            original.3,
            original.4,
            1,
            original.6 + 1,
            original.7,
            original.8,
        ),
    ] {
        assert!(!moved_original(original, bad));
    }
    assert!(effect(local::Publication::RefReturned).is_none());
    assert!(!steps(false, false).contains(&local::Publication::RenameNewLogReturned));
    assert!(!steps(true, false).contains(&local::Publication::RenameConfigReturned));
}
