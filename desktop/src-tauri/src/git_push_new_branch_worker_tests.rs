//! Same private request/candidate/terminal decoder, inert original-shaped DATA.
//! These tests do not issue a real credential or construct a native join.
use super::*;
use crate::git_push_protocol::new_branch::tests as data;

fn request(apply: bool) -> Request {
    let ordinary = tests::request(false);
    Request::from_push_original(
        &ordinary.id,
        &Action::Push(data::action()),
        &ordinary.context,
        &tests::native(),
        ordinary.clock,
        apply.then(|| ApplyBinding {
            review: Review::Push(data::review()),
            journal_revision: 11,
        }),
        tests::target(),
    )
    .unwrap()
}
fn line(value: &Value) -> Vec<u8> {
    let mut raw = serde_json::to_vec(value).unwrap();
    raw.push(b'\n');
    raw
}
fn candidate(r: &Request) -> Candidate {
    r.candidate(&line(
        &json!({"protocol":PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,
        "reviewDigest":data::review().review_digest,"intent":data::intent()}),
    ))
    .unwrap()
}
fn terminal(r: &Request, apply: bool) -> Value {
    json!({"protocol":PROTOCOL,"kind":"terminal","id":r.id,"digest":r.digest,
        "phase":if apply {"apply"}else{"prepare"},"action":"push-new-branch","status":"ok","reason":null,
        "result":if apply { json!({"operationId":r.id,"action":"push-new-branch","state":"succeeded",
            "settlement":"settled","reason":null,"observation":null,"intent":data::intent(),
            "effectPhase":"remote-returned","retainedPaths":[]})
        }else{json!({"review":data::review(),"diff":null})},
        "transmission":if apply {json!(tests::returned())}else{Value::Null},
        "firstFailureNs":null,"cleanupEndNs":r.clock.hard_end_ns,
        "control":{"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}})
}

#[test]
fn fixed_original_request_preserves_new_kind_null_source_and_same_clock() {
    let r = request(false);
    let body: Value = serde_json::from_slice(r.bytes()).unwrap();
    assert_eq!(body["action"]["kind"], "push-new-branch");
    assert!(body["action"]["remote"].is_null());
    assert!(r.action.kind() == Kind::PushNewBranch);
    assert_eq!(body["clock"]["hardEndNs"], json!(55_000_000_000u64));
    assert!(r.push_go("inert-noncredential").is_ok());
    let ordinary = tests::request(false);
    assert!(Request::from_push_original(
        &r.id,
        &r.action,
        &r.context,
        &tests::native(),
        r.clock,
        Some(ApplyBinding {
            review: Review::Push(crate::git_push_protocol::tests::review()),
            journal_revision: 11
        }),
        tests::target()
    )
    .is_err());
    assert_ne!(r.digest, ordinary.digest);
    let mut wrong_head = tests::native();
    wrong_head.files.head.sha256 = hash(b"detached\n");
    assert!(Request::from_push_original(
        &r.id,
        &r.action,
        &r.context,
        &wrong_head,
        r.clock,
        None,
        tests::target()
    )
    .is_err());
}

#[test]
fn prepared_no_send_and_apply_ack_remain_bound_to_explicit_kind() {
    let r = request(false);
    let v = terminal(&r, false);
    assert!(r
        .terminal(&line(&v), None)
        .unwrap()
        .result
        .get("diff")
        .is_none());
    let mut wrong = v;
    wrong["action"] = json!("push");
    assert!(r.terminal(&line(&wrong), None).is_err());
    let r = request(true);
    let c = candidate(&r);
    assert!(r.push_ack(&c, 12).is_ok());
    assert!(r.ack(&c, 12).is_err());
    assert!(tests::request(true).push_ack(&c, 12).is_err());
    let mut ordinary = data::intent();
    ordinary.action = push::Kind::Push;
    let wrong = json!({"protocol":PROTOCOL,"kind":"candidate","id":r.id,"digest":r.digest,
        "reviewDigest":data::review().review_digest,"intent":ordinary});
    assert!(r.candidate(&line(&wrong)).is_err());
}

#[test]
fn create_only_return_uses_same_final_data_checks_and_unknown_never_reports_success() {
    let r = request(true);
    let c = candidate(&r);
    let v = terminal(&r, true);
    let decoded = r.terminal(&line(&v), Some(&c)).unwrap();
    assert!(
        crate::git_push_state::FinalData::from_returned(&r, &c, &decoded, &tests::returned())
            .is_ok()
    );
    let mut wrong = v.clone();
    wrong["result"]["action"] = json!("push");
    assert!(r.terminal(&line(&wrong), Some(&c)).is_err());
    let mut unknown = v;
    unknown["status"] = json!("cleanup-unknown");
    unknown["reason"] = json!("cleanup-unknown");
    unknown["result"] = Value::Null;
    unknown["transmission"] = Value::Null;
    assert!(!r
        .terminal(&line(&unknown), Some(&c))
        .unwrap()
        .child_declared_settled());
    unknown["transmission"] = json!(tests::returned());
    assert!(r.terminal(&line(&unknown), Some(&c)).is_err());
}
