//! Closed main-window DATA only. Decoding never constructs a Review, Grant,
//! Document, native Lane, runtime or Store permission.
use super::*;
use serde_json::json;

fn allow() -> Value {
    json!({"projectId":"project-1","reviewId":"00000000000000000000000000000001",
        "expectedReserveRevision":7,"expectedAllowRevision":"0000000000000000","consentVersion":wire::CONSENT})
}
#[test]
fn allow_requires_exact_review_revision_and_consent_without_caller_authority() {
    let value = allow();
    let decoded = decode_allow(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(decoded.project_id, "project-1");
    assert_eq!(decoded.expected_reserve_revision, 7);
    assert_eq!(decoded.expected_allow_revision, "0000000000000000");
    for field in [
        "projectId",
        "reviewId",
        "expectedReserveRevision",
        "expectedAllowRevision",
        "consentVersion",
    ] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(decode_allow(&serde_json::to_vec(&missing).unwrap()).is_err());
    }
    for (field, bad) in [
        ("projectId", json!("../project")),
        ("reviewId", json!("00000000000000000000000000000000")),
        ("expectedReserveRevision", json!(0)),
        ("expectedReserveRevision", json!(u32::MAX)),
        ("expectedReserveRevision", json!("7")),
        ("expectedAllowRevision", json!(0)),
        ("expectedAllowRevision", json!(null)),
        ("expectedAllowRevision", json!("0")),
        ("expectedAllowRevision", json!("000000000000000A")),
        ("expectedAllowRevision", json!("0000000000000000\n")),
        ("expectedAllowRevision", json!("ffffffffffffffff")),
        ("consentVersion", json!("agent-local-build-once-v1")),
        ("source", json!({})),
        ("candidateId", json!("not accepted")),
        ("account", json!({})),
        ("apply", json!(true)),
    ] {
        let mut wrong = value.clone();
        wrong[field] = bad;
        assert!(
            decode_allow(&serde_json::to_vec(&wrong).unwrap()).is_err(),
            "{field}"
        );
    }
    let bytes = serde_json::to_vec(&value).unwrap();
    let duplicate = format!(
        "{{\"projectId\":\"different\",{}",
        &std::str::from_utf8(&bytes).unwrap()[1..]
    );
    assert!(decode_allow(duplicate.as_bytes()).is_err());
    let mut large = vec![b' '; wire::RAW_LIMIT - 96];
    large.extend(&bytes);
    assert!(decode_allow(&large).is_err());
}

#[test]
fn original_main_revision_fences_revoke_before_first_allow_and_between_real_cuts() {
    let state = State::default();
    // The actual MAIN accessor also works before a Service/Grant exists.
    let checked = state.main_access(wire::Access::empty()).unwrap();
    let expected = allow_revision(&checked.allow_revision).unwrap();
    assert_eq!(expected, 0);
    assert!(state.service.is_none() && state.grant.is_none());
    assert!(state.invalidate_allow()); // Revoke overtakes the delayed first cut.
    assert_eq!(state.claim_allow(expected), Err(Error::Conflict));
    let fresh = state.main_access(wire::Access::empty()).unwrap();
    let expected = allow_revision(&fresh.allow_revision).unwrap();
    let successor = state.claim_allow(expected).unwrap();
    assert!(state.allow_current(successor));
    assert_eq!(state.claim_allow(expected), Err(Error::Conflict)); // Never reused.
    assert!(state.invalidate_allow()); // Same original Host-wait gap, no new clock.
    assert!(!state.allow_current(successor));
    assert!(state.service.is_none() && state.grant.is_none());

    // Only MAIN's envelope changes. CLI Access remains the exact old DTO.
    let main = serde_json::to_value(state.main_access(wire::Access::empty()).unwrap()).unwrap();
    let mut old = serde_json::to_value(wire::Access::empty()).unwrap();
    assert_eq!(old.as_object().unwrap().len(), 10);
    old["allowRevision"] = json!("0000000000000003");
    assert_eq!(main, old);
    assert!(serde_json::to_vec(&main).unwrap().len() <= wire::STATUS_LIMIT);
}

#[test]
fn main_revision_overflow_is_absorbing_and_cannot_wrap_or_issue_another_stamp() {
    let state = State::default();
    state.epoch.store(u64::MAX - 1, Ordering::SeqCst);
    assert_eq!(allow_revision("fffffffffffffffe"), Some(u64::MAX - 1));
    assert_eq!(state.claim_allow(u64::MAX - 1), Err(Error::StateUnknown));
    assert_eq!(state.epoch.load(Ordering::SeqCst), u64::MAX);
    assert_eq!(state.allow_epoch(), Err(Error::StateUnknown));
    assert_eq!(state.claim_allow(0), Err(Error::StateUnknown));
    assert!(!state.allow_current(u64::MAX));
    assert!(!state.invalidate_allow());
    assert!(state.main_access(wire::Access::empty()).is_err());
    assert_eq!(state.epoch.load(Ordering::SeqCst), u64::MAX);
    assert!(state.service.is_none() && state.grant.is_none());
}
#[test]
fn status_and_revoke_accept_only_bounded_empty_raw_objects() {
    decode_empty(b"{}").unwrap();
    for bytes in [
        b"".as_slice(),
        b"null",
        b"[]",
        b"true",
        b"{\"projectId\":\"project-1\"}",
        b"{}{}",
    ] {
        assert!(decode_empty(bytes).is_err());
    }
    let mut boundary = vec![b' '; wire::RAW_LIMIT - 98];
    boundary.extend(b"{}");
    decode_empty(&boundary).unwrap();
    boundary.push(b' ');
    assert!(decode_empty(&boundary).is_err());
}
