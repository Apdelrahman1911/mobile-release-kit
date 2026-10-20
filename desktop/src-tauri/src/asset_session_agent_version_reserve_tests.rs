//! Closed main-window DATA only. Decoding never constructs a Review, Grant,
//! Document, native Lane, runtime or Store permission.
use super::*;
use serde_json::json;

fn allow() -> Value {
    json!({"projectId":"project-1","reviewId":"00000000000000000000000000000001",
        "expectedReserveRevision":7,"consentVersion":wire::CONSENT})
}
#[test]
fn allow_requires_exact_review_revision_and_consent_without_caller_authority() {
    let value = allow();
    let decoded = decode_allow(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(decoded.project_id, "project-1");
    assert_eq!(decoded.expected_reserve_revision, 7);
    for field in [
        "projectId",
        "reviewId",
        "expectedReserveRevision",
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
