//! Real closed codecs over inert DATA. No Git, token source, IO, native
//! admission, SourceBook successor or joined-publication witness is supplied.
use super::*;
use crate::git_local_protocol::{self as local, fetch_worker as worker};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
pub(crate) fn raw(value: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    bytes
}
pub(crate) fn action() -> Action {
    Action {
        kind: Kind::Fetch,
        expected_revision: "a".repeat(64),
        expected_reference_revision: "b".repeat(64),
        remote: "origin".into(),
        reference: "refs/heads/main".into(),
        connection_session_id: "github-session-1".into(),
        expected_connection_revision: 4,
    }
}
pub(crate) fn review() -> Review {
    Review {
        action: Kind::Fetch,
        remote: "origin".into(),
        repository: "owner/app".into(),
        reference: "refs/heads/main".into(),
        target_ref: "refs/remotes/origin/main".into(),
        expected_target: Some("3".repeat(40)),
        candidate_ref_oid: "4".repeat(40),
        expected_revision: "a".repeat(64),
        expected_reference_revision: "b".repeat(64),
        head: Some("1".repeat(40)),
        branch: Some("refs/heads/local".into()),
        expected_index: "2".repeat(64),
        account_id: "11".into(),
        repository_id: "22".into(),
        login: "owner".into(),
        review_digest: "c".repeat(64),
    }
}
pub(crate) fn intent() -> Intent {
    let r = review();
    Intent {
        action: Kind::Fetch,
        review_digest: r.review_digest,
        expected_revision: r.expected_revision,
        expected_reference_revision: r.expected_reference_revision,
        expected_ref: r.branch,
        expected_head: r.head,
        expected_index: r.expected_index,
        target_ref: r.target_ref,
        expected_target: r.expected_target,
        candidate_ref_oid: r.candidate_ref_oid,
        pack_oid: "5".repeat(40),
        pack_sha256: "d".repeat(64),
        pack_bytes: 100,
        index_sha256: "e".repeat(64),
        index_bytes: 50,
    }
}
pub(crate) fn native() -> local::Native {
    let file = |uid, mode| local::Snapshot {
        identity: (1, 2, mode, uid, 1001, 1, 12, 123, 456),
        sha256: "2".repeat(64),
    };
    local::Native {
        uid: 1001,
        gid: 1001,
        root: "/inert/project".into(),
        directories: local::Directories {
            root: (1, 2, 0o40700, 1001, 1001),
            git: (1, 3, 0o40700, 1001, 1001),
            objects: (1, 4, 0o40700, 1001, 1001),
        },
        tool: file(0, 0o100755),
        files: local::Files {
            head: file(1001, 0o100600),
            config: file(1001, 0o100600),
            index: Some(file(1001, 0o100600)),
        },
    }
}
pub(crate) fn target(phase: local::Phase) -> worker::Target {
    let r = review();
    worker::Target {
        repository: r.repository,
        login: r.login,
        account_id: r.account_id,
        repository_id: r.repository_id,
        reference: r.reference,
        oid: (phase == local::Phase::Apply).then_some(r.candidate_ref_oid),
    }
}
pub(crate) fn request(phase: local::Phase) -> local::Request {
    local::Request::from_fetch_original(
        "fetch-original",
        &local::Action::Fetch(action()),
        &local::Context {
            project_id: "project-1".into(),
            generation: 2,
            revision: "document-4".into(),
        },
        &native(),
        local::Clock {
            work_end_ns: 100_000_000_000,
            hard_end_ns: 110_000_000_000,
        },
        (phase == local::Phase::Apply).then(|| local::ApplyBinding {
            review: local::Review::Fetch(review()),
            journal_revision: 8,
        }),
        target(phase),
    )
    .unwrap()
}
fn binding() -> Option<local::ApplyBinding> {
    Some(local::ApplyBinding {
        review: local::Review::Fetch(review()),
        journal_revision: 8,
    })
}
pub(crate) fn candidate(r: &local::Request) -> local::Candidate {
    r.candidate(&raw(
        json!({"protocol":worker::PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,
        "reviewDigest":review().review_digest,"intent":intent()}),
    ))
    .unwrap()
}
pub(crate) fn keep() -> worker::Keep {
    let i = intent();
    let n = format!("mrk-git-fetch/1 {}\n", i.review_digest).len() as u64;
    worker::Keep {
        pack_oid: i.pack_oid,
        review_digest: i.review_digest,
        identity: [1, 60, 0o100600, n, 123, 456, 1001, 1001, 1],
        parent_before: [1, 4, 0o40700, 96, 123, 456, 1001, 1001],
        parent_after: [1, 4, 0o40700, 128, 124, 457, 1001, 1001],
    }
}
pub(crate) fn returned() -> Value {
    let i = intent();
    json!({"phase":"ref-published","pack":[1,50,0o100444,i.pack_bytes,123,456,1001,1001,1],
        "index":[1,51,0o100444,i.index_bytes,123,456,1001,1001,1],
        "reference":{"name":i.target_ref,"oid":i.candidate_ref_oid,"identity":[1,52,0o100644,41,123,456],"parent":[1,53,0o40700,96,123,456]},
        "log":{"kind":"absent","identity":null,"sha256":hash(b"absent")},"logParent":[1,54,0o40700,96,123,456,1001,1001]})
}
pub(crate) fn terminal(r: &local::Request) -> Value {
    let result = if r.phase == local::Phase::Prepare {
        json!({"review":review(),"diff":null})
    } else {
        json!({"operationId":r.id,"action":"fetch","state":"succeeded","settlement":"settled","reason":null,
            "observation":null,"intent":intent(),"effectPhase":"ref-published","retainedPaths":[]})
    };
    json!({"protocol":worker::PROTOCOL,"kind":"terminal","id":r.id,"digest":r.digest,"phase":r.phase,"action":"fetch",
        "status":"ok","reason":null,"result":result,"publication":if r.phase==local::Phase::Apply {returned()} else {Value::Null},
        "firstFailureNs":null,"cleanupEndNs":r.clock.hard_end_ns,
        "control":{"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}})
}

#[test]
fn fetch_uses_only_the_existing_five_strict_commands_without_url_token_or_exec_input() {
    let good = json!({"projectId":"project-1","expectedDocumentRevision":4,"action":action()});
    assert!(matches!(
        local::decode_command("git_local_prepare", &raw(good.clone())).unwrap(),
        local::Command::Prepare(_)
    ));
    for (key, value) in [
        ("url", json!("https://elsewhere.invalid")),
        ("token", json!("INERT")),
        ("executable", json!("git")),
        ("force", json!(false)),
        ("paths", json!([])),
        ("capability", json!("claimed")),
    ] {
        let mut bad = good.clone();
        bad["action"][key] = value;
        assert!(local::decode_command("git_local_prepare", &raw(bad)).is_err());
    }
    assert!(local::decode_command("git_fetch_execute", &raw(good)).is_err());
    assert!(local::decode_command(
        "git_local_prepare",
        b"{\"projectId\":\"a\",\"projectId\":\"b\"}"
    )
    .is_err());
    for remote in ["-origin", "a/b", "a b", "a;sh", ""] {
        let mut a = action();
        a.remote = remote.into();
        assert!(!a.valid());
    }
    for name in [
        "refs/tags/v1",
        "refs/heads/a:x",
        "refs/heads/a..b",
        "refs/heads/a.lock",
    ] {
        let mut a = action();
        a.reference = name.into();
        assert!(!a.valid());
    }
}

#[test]
fn equal_tip_prepare_is_review_data_but_apply_cannot_start() {
    let r = request(local::Phase::Prepare);
    let mut row = terminal(&r);
    row["result"]["review"]["expectedTarget"] = row["result"]["review"]["candidateRefOid"].clone();
    let parsed = r.terminal(&raw(row), None).unwrap();
    let local::Review::Fetch(v) = parsed.review().unwrap() else {
        panic!()
    };
    assert!(v.up_to_date());
    assert!(local::Request::from_fetch_original(
        &r.id,
        &r.action,
        &r.context,
        &native(),
        r.clock,
        Some(local::ApplyBinding {
            review: local::Review::Fetch(v),
            journal_revision: 8
        }),
        target(local::Phase::Apply)
    )
    .is_err());
}

#[test]
fn private_request_requires_original_repo_snapshot_review_target_and_same_clock() {
    let r = request(local::Phase::Apply);
    let row: Value = serde_json::from_slice(r.bytes()).unwrap();
    assert!(
        row["protocol"] == worker::PROTOCOL
            && row["native"].is_object()
            && row.get("initialization").is_none()
    );
    assert!(local::Request::from_original(
        &r.id,
        &r.action,
        &r.context,
        &native(),
        r.clock,
        binding()
    )
    .is_err());
    let mut n = native();
    n.files.index.as_mut().unwrap().sha256 = "f".repeat(64);
    assert!(local::Request::from_fetch_original(
        &r.id,
        &r.action,
        &r.context,
        &n,
        r.clock,
        binding(),
        target(local::Phase::Apply)
    )
    .is_err());
    for field in [
        "accountId",
        "repositoryId",
        "repository",
        "login",
        "reference",
        "oid",
    ] {
        // Target has no Deserialize route: mutate the exact DATA struct, not a
        // new public issuer/factory accepting a caller object.
        let mut target = target(local::Phase::Apply);
        match field {
            "accountId" => target.account_id = "99".into(),
            "repositoryId" => target.repository_id = "99".into(),
            "repository" => target.repository = "other/app".into(),
            "login" => target.login = "other".into(),
            "reference" => target.reference = "refs/heads/other".into(),
            _ => target.oid = Some("9".repeat(40)),
        }
        assert!(local::Request::from_fetch_original(
            &r.id,
            &r.action,
            &r.context,
            &native(),
            r.clock,
            binding(),
            target
        )
        .is_err());
    }
    assert!(local::Request::from_fetch_original(
        &r.id,
        &r.action,
        &r.context,
        &native(),
        local::Clock {
            hard_end_ns: r.clock.hard_end_ns + 1,
            ..r.clock
        },
        binding(),
        target(local::Phase::Apply)
    )
    .is_err());
}

#[test]
fn private_go_has_one_bounded_copy_and_ordinary_ack_cannot_serve_fetch() {
    let r = request(local::Phase::Apply);
    let go = r.fetch_go("INERT_NOT_A_CREDENTIAL").unwrap();
    assert!(go.len() <= worker::GO_LIMIT);
    let v: Value = serde_json::from_slice(&go).unwrap();
    assert!(v["digest"] == r.digest && v["kind"] == "go");
    assert!(!String::from_utf8(r.bytes().to_vec())
        .unwrap()
        .contains("INERT_NOT_A_CREDENTIAL"));
    for value in [String::new(), "line\nbreak".into(), "a".repeat(4097)] {
        assert!(r.fetch_go(&value).is_err());
    }
    let c = candidate(&r);
    assert!(r.ack(&c, 9).is_err());
    assert!(r.fetch_ack(&c, 9, &keep()).unwrap().len() <= worker::ACK_LIMIT);
    for revision in [0, 8, 10] {
        assert!(r.fetch_ack(&c, revision, &keep()).is_err());
    }
    for field in 0..3 {
        let mut k = keep();
        match field {
            0 => k.pack_oid = "9".repeat(40),
            1 => k.identity[8] = 2,
            _ => k.parent_after[1] += 1,
        }
        assert!(r.fetch_ack(&c, 9, &k).is_err());
    }
}

#[test]
fn candidate_cannot_change_review_or_exceed_fixed_pack_and_index_bounds() {
    let r = request(local::Phase::Apply);
    for (key, value) in [
        ("expectedIndex", json!("f".repeat(64))),
        ("expectedTarget", json!("6".repeat(40))),
        ("targetRef", json!("refs/remotes/elsewhere/main")),
        ("reviewDigest", json!("f".repeat(64))),
        ("packBytes", json!(0)),
        ("indexBytes", json!(FILE_LIMIT + 1)),
        ("candidateRefOid", json!("6".repeat(40))),
    ] {
        let mut i = serde_json::to_value(intent()).unwrap();
        i[key] = value;
        let row = json!({"protocol":worker::PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,
            "reviewDigest":review().review_digest,"intent":i});
        assert!(r.candidate(&raw(row)).is_err());
    }
}

#[test]
fn actual_terminal_parser_binds_account_and_rejects_success_with_fatal_control() {
    let r = request(local::Phase::Prepare);
    assert!(r
        .terminal(&raw(terminal(&r)), None)
        .unwrap()
        .child_declared_settled());
    for key in ["accountId", "repositoryId", "login", "repository"] {
        let mut row = terminal(&r);
        row["result"]["review"][key] = json!(if key.ends_with("Id") {
            "99"
        } else if key == "repository" {
            "other/app"
        } else {
            "other"
        });
        assert!(r.terminal(&raw(row), None).is_err());
    }
    let mut row = terminal(&r);
    row["control"]["reason"] = json!("target-changed");
    assert!(r.terminal(&raw(row), None).is_err());
    let mut row = terminal(&r);
    row.as_object_mut().unwrap().remove("control");
    assert!(r.terminal(&raw(row), None).is_err());
}

#[test]
fn returned_ref_pack_identity_is_required_but_never_native_finality() {
    let r = request(local::Phase::Apply);
    let c = candidate(&r);
    let good = terminal(&r);
    let t = r.terminal(&raw(good.clone()), Some(&c)).unwrap();
    assert!(
        t.child_declared_settled() && t.fetch_publication.is_some() && t.fetch_control.is_some()
    );
    assert!(r.terminal(&raw(good.clone()), None).is_err());
    for field in ["publication", "reference", "index", "log"] {
        let mut row = good.clone();
        if field == "publication" {
            row[field] = Value::Null;
        } else {
            row["publication"][field] = Value::Null;
        }
        assert!(r.terminal(&raw(row), Some(&c)).is_err());
    }
    for n in [0, 3] {
        let mut row = good.clone();
        row["publication"]["pack"][8] = json!(n);
        assert!(r.terminal(&raw(row), Some(&c)).is_err());
    }
    let mut row = good;
    row["result"]["observation"] = json!({"revision":"forged"});
    assert!(r.terminal(&raw(row), Some(&c)).is_err());
}

#[test]
fn partial_return_needs_exact_effect_and_remains_recovery_not_success() {
    let r = request(local::Phase::Apply);
    let c = candidate(&r);
    let mut row = terminal(&r);
    row["result"]["state"] = json!("recovery-required");
    row["result"]["reason"] = json!("fetch-output");
    row["result"]["effectPhase"] = json!("pack-linked");
    row["result"]["retainedPaths"] =
        json!([format!("objects/pack/pack-{}.pack", intent().pack_oid)]);
    row["publication"]["phase"] = json!("pack-linked");
    for k in ["index", "reference", "log", "logParent"] {
        row["publication"][k] = Value::Null;
    }
    row["firstFailureNs"] = json!(99_000_000_000u64);
    row["cleanupEndNs"] = json!(109_000_000_000u64);
    assert!(r.terminal(&raw(row.clone()), Some(&c)).is_ok());
    let mut bad = row.clone();
    bad["result"]["state"] = json!("succeeded");
    bad["result"]["reason"] = Value::Null;
    assert!(r.terminal(&raw(bad), Some(&c)).is_err());
    row["publication"]["phase"] = json!("objects-linked");
    assert!(r.terminal(&raw(row), Some(&c)).is_err());
}

#[test]
fn unknown_preserves_control_data_without_a_settled_claim_and_rejects_extended_clock() {
    let r = request(local::Phase::Prepare);
    let mut row = terminal(&r);
    row["status"] = json!("cleanup-unknown");
    row["reason"] = json!("cleanup-unknown");
    row["result"] = Value::Null;
    row["firstFailureNs"] = json!(99_000_000_000u64);
    row["cleanupEndNs"] = json!(109_000_000_000u64);
    row["control"]["reason"] = json!("rate-limited");
    row["control"]["cooldownSeconds"] = json!(120);
    let t = r.terminal(&raw(row.clone()), None).unwrap();
    assert!(!t.child_declared_settled());
    assert_eq!(t.fetch_control.unwrap().cooldown_seconds, Some(120));
    let mut bad = row.clone();
    bad["cleanupEndNs"] = json!(110_000_000_000u64);
    assert!(r.terminal(&raw(bad), None).is_err());
    let mut bad = row.clone();
    bad["control"]["reason"] = json!("unauthorized");
    assert!(r.terminal(&raw(bad), None).is_err());
    let mut doubled = raw(row);
    doubled.extend_from_slice(b"{}\n");
    assert!(r.terminal(&doubled, None).is_err());
    assert!(r
        .terminal(&vec![b'x'; worker::OUTPUT_LIMIT + 1], None)
        .is_err());
}
