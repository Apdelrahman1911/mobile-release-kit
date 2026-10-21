use super::*;
use crate::git_push_protocol::tests as data;

pub(crate) fn target() -> Target {
    Target {
        repository: "owner/repository".into(),
        login: "owner".into(),
        account_id: "12".into(),
        repository_id: "34".into(),
    }
}
pub(crate) fn native() -> Native {
    let snapshot = |mode, uid, size, digest: &str| Snapshot {
        identity: (1, 2, mode, uid, 20, 1, size, 1, 1),
        sha256: digest.into(),
    };
    Native {
        uid: 501,
        gid: 20,
        root: "/Users/user/project".into(),
        directories: Directories {
            root: (1, 3, 0o40700, 501, 20),
            git: (1, 4, 0o40700, 501, 20),
            objects: (1, 5, 0o40700, 501, 20),
        },
        tool: snapshot(0o100755, 0, 123, &"e".repeat(64)),
        files: Files {
            head: snapshot(0o100600, 501, 21, &hash(b"ref: refs/heads/main\n")),
            config: snapshot(0o100600, 501, 30, &"f".repeat(64)),
            index: Some(snapshot(0o100600, 501, 64, &"c".repeat(64))),
        },
    }
}
pub(crate) fn request(apply: bool) -> Request {
    let binding = apply.then(|| ApplyBinding {
        review: Review::Push(data::review()),
        journal_revision: 11,
    });
    Request::from_push_original(
        "git-7",
        &Action::Push(data::action()),
        &Context {
            project_id: "project-1".into(),
            generation: 1,
            revision: "revision-1".into(),
        },
        &native(),
        Clock {
            work_end_ns: 45_000_000_000,
            hard_end_ns: 55_000_000_000,
        },
        binding,
        target(),
    )
    .unwrap()
}
pub(crate) fn candidate(r: &Request) -> Candidate {
    let mut bytes = serde_json::to_vec(
        &json!({"protocol":PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,
        "reviewDigest":data::review().review_digest,"intent":data::intent()}),
    )
    .unwrap();
    bytes.push(b'\n');
    r.candidate(&bytes).unwrap()
}
pub(crate) fn returned() -> Returned {
    Returned {
        body: Body {
            bytes: 256,
            sha256: "1".repeat(64),
            pack_bytes: 64,
            pack_sha1: "2".repeat(40),
            objects: 1,
        },
        advertisement: "3".repeat(64),
        response: Response {
            outcome: "ok".into(),
            sha256: "4".repeat(64),
            bytes: 128,
            progress_bytes: 0,
        },
        after: "5".repeat(64),
    }
}
fn terminal(r: &Request, apply: bool) -> Value {
    json!({"protocol":PROTOCOL,"kind":"terminal","id":r.id,"digest":r.digest,"phase":if apply {"apply"}else{"prepare"},
        "action":"push","status":"ok","reason":null,"result":if apply {
            json!({"operationId":r.id,"action":"push","state":"succeeded","settlement":"settled","reason":null,
                "observation":null,"intent":data::intent(),"effectPhase":"remote-returned","retainedPaths":[]})
        } else {json!({"review":data::review(),"diff":null})},"transmission":if apply {json!(returned())}else{Value::Null},
        "firstFailureNs":null,"cleanupEndNs":r.clock.hard_end_ns,
        "control":{"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}})
}
fn decode(r: &Request, v: &Value, c: Option<&Candidate>) -> Result<Terminal, BridgeError> {
    let mut raw = serde_json::to_vec(v).unwrap();
    raw.push(b'\n');
    r.terminal(&raw, c)
}
#[test]
fn push_quote_preserves_shared_data_writer_remote_and_code_bounds() {
    const M: usize = 1024 * 1024;
    let code = crate::macos_history_inventory::CODE_CONTROL_RESERVE;
    assert_eq!(BODY_CALLS * BODY_CALL_BYTES + BODY_REMAINDER, 14_385_152);
    assert_eq!(BODY_LEASES, 2);
    assert_eq!(
        admission_bytes(16 * M, code + 16 * M + REMOTE_BACKING),
        Some(code + 72 * M)
    );
    assert_eq!(admission_bytes(48 * M, code + 16 * M + REMOTE_BACKING), Some(232 * M));
    assert_eq!(admission_bytes(64 * M, code + REMOTE_BACKING), Some(232 * M));
    assert_eq!(admission_bytes(48 * M + 1, code + 16 * M + REMOTE_BACKING), None);
    assert_eq!(admission_bytes(64 * M + 1, code + REMOTE_BACKING), None);
    assert_eq!(admission_bytes(0, code + 16 * M + REMOTE_BACKING + 1), None);
    assert_eq!(admission_bytes(0, code + REMOTE_BACKING - 1), None);
    assert_eq!(admission_bytes(usize::MAX, usize::MAX), None);
}
#[test]
fn original_request_binds_attached_head_and_review_account_while_go_is_private() {
    let r = request(true);
    let go = r.push_go("test-only-noncredential").unwrap();
    let v: Value = serde_json::from_slice(&go).unwrap();
    assert_eq!(v["protocol"], PROTOCOL);
    assert_eq!(v["id"], r.id);
    assert_eq!(v["digest"], r.digest);
    assert_eq!(v["token"], "test-only-noncredential");
    assert!(r.push_go("bad\n").is_err());
    assert!(r.push_go(&"a".repeat(4097)).is_err());
    let mut n = native();
    n.files.head.sha256 = hash(b"ref: refs/heads/other\n");
    assert!(Request::from_push_original(
        "git-7",
        &r.action,
        &r.context,
        &n,
        r.clock,
        r.binding.as_ref().map(|b| ApplyBinding {
            review: b.review.clone(),
            journal_revision: b.journal_revision
        }),
        target()
    )
    .is_err());
    let mut foreign = target();
    foreign.account_id = "99".into();
    assert!(Request::from_push_original(
        "git-7",
        &r.action,
        &r.context,
        &native(),
        r.clock,
        r.binding.as_ref().map(|b| ApplyBinding {
            review: b.review.clone(),
            journal_revision: b.journal_revision
        }),
        foreign
    )
    .is_err());
}
#[test]
fn exact_candidate_ack_once_revision_has_no_fetch_keep_or_mutable_body_permission() {
    let r = request(true);
    let c = candidate(&r);
    let ack = r.push_ack(&c, 12).unwrap();
    let v: Value = serde_json::from_slice(&ack).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 6);
    assert_eq!(v["candidateDigest"], c.digest);
    assert_eq!(v["journalRevision"], 12);
    assert!(r.push_ack(&c, 11).is_err());
    assert!(request(false).push_ack(&c, 12).is_err());
    let mut other = c;
    other.intent = Intent::Push({
        let mut i = data::intent();
        i.new_oid = "9".repeat(40);
        i
    });
    assert!(r.push_ack(&other, 12).is_err());
}
#[test]
fn review_dry_run_accepts_only_exact_no_transmission_result_and_no_child_authority() {
    let r = request(false);
    let v = terminal(&r, false);
    let public = decode(&r, &v, None).unwrap();
    assert_eq!(public.result.as_object().unwrap().len(), 1);
    assert!(public.result.get("diff").is_none());
    let mut bad = v.clone();
    bad["transmission"] = json!(returned());
    assert!(decode(&r, &bad, None).is_err());
    let mut bad = v.clone();
    bad["result"]["review"]["accountId"] = json!("99");
    assert!(decode(&r, &bad, None).is_err());
    let mut bad = v;
    bad["publication"] = json!("push-returned");
    assert!(decode(&r, &bad, None).is_err());
}
#[test]
fn apply_requires_complete_same_original_return_and_late_stop_cannot_be_success() {
    let r = request(true);
    let c = candidate(&r);
    let v = terminal(&r, true);
    let decoded = decode(&r, &v, Some(&c)).unwrap();
    assert!(
        crate::git_push_state::FinalData::from_returned(&r, &c, &decoded, &returned())
            .unwrap()
            .successful(Some(&data::intent()))
    );
    assert!(decode(&r, &v, None).is_err());
    let mut bad = v.clone();
    bad["transmission"] = Value::Null;
    assert!(decode(&r, &bad, Some(&c)).is_err());
    let mut bad = v.clone();
    bad["firstFailureNs"] = json!(44_000_000_000u64);
    bad["cleanupEndNs"] = json!(54_000_000_000u64);
    assert!(decode(&r, &bad, Some(&c)).is_err());
    bad["result"]["state"] = json!("recovery-required");
    bad["result"]["reason"] = json!("cancelled");
    assert!(decode(&r, &bad, Some(&c)).is_ok());
    let mut wrong = returned();
    wrong.body.bytes = push::BODY_LIMIT + 1;
    let mut bad = v;
    bad["transmission"] = json!(wrong);
    assert!(decode(&r, &bad, Some(&c)).is_err());
}
#[test]
fn cleanup_unknown_never_returns_progress_or_reconstructs_a_send_receipt() {
    let r = request(true);
    let mut v = terminal(&r, true);
    v["status"] = json!("cleanup-unknown");
    v["reason"] = json!("cleanup-unknown");
    v["result"] = Value::Null;
    v["transmission"] = Value::Null;
    let decoded = decode(&r, &v, None).unwrap();
    assert!(!decoded.child_declared_settled());
    v["transmission"] = json!(returned());
    assert!(decode(&r, &v, None).is_err());
}

#[test]
fn known_retained_apply_accepts_only_original_flat_or_nested_diagnostic_shape() {
    let r = request(true);
    let c = candidate(&r);
    let mut v = terminal(&r, true);
    v["result"]["state"] = json!("recovery-required");
    v["result"]["reason"] = json!("cancelled");
    v["firstFailureNs"] = json!(44_000_000_000u64);
    v["cleanupEndNs"] = json!(54_000_000_000u64);
    for path in ["mrk-git-push-inert", "mrk-git-original/mrk-git-push-inert"] {
        v["result"]["retainedPaths"] = json!([path]);
        let decoded = decode(&r, &v, Some(&c)).unwrap();
        assert_eq!(decoded.result["retainedPaths"], json!([path]));
        assert_eq!(decoded.result["state"], "recovery-required");
    }
    for path in [
        "/mrk-git-push-a",
        "../mrk-git-push-a",
        "mrk-git-a/mrk-git-push-b/extra",
        "mrk-git-a/../mrk-git-push-b",
        "mrk-git-push-a/mrk-git-push-b",
        "mrk-git-/mrk-git-push-b",
    ] {
        v["result"]["retainedPaths"] = json!([path]);
        assert!(decode(&r, &v, Some(&c)).is_err());
    }
    v["result"]["retainedPaths"] = json!(["mrk-git-a/mrk-git-push-b", "mrk-git-push-c"]);
    assert!(decode(&r, &v, Some(&c)).is_err());
}
