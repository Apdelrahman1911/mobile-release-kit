use super::*;
use crate::service_protocol as wire;
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn row() -> Status {
    Status {
        origin: Query {
            project_id: id('a'),
            service_instance: id('b'),
            request_id: id('c'),
            purpose: Purpose::PlayCleanup,
        },
        consent_id: id('d'),
        revision: 1,
        state: State::Queued,
        settlement: Settlement::Pending,
        operation_id: None,
        reason: None,
        effect: Effect::NotSent,
        do_not_replay: true,
    }
}
#[test]
fn closed_request_accepts_only_three_ids_and_consent_not_provider_material() {
    let q = row();
    let request = wire::Request {
        version: 1,
        request_id: id('e'),
        request: wire::RequestBody::PlayCleanupSubmit(Submit {
            origin: q.origin.clone(),
            consent_id: q.consent_id,
        }),
    };
    let bytes = wire::encode_request(&request).unwrap();
    assert_eq!(wire::decode_request(&bytes).unwrap(), request);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for key in ["editId", "key", "workflow", "branch", "confirmation"] {
        let mut bad = value.clone();
        bad["request"]["params"][key] = serde_json::json!("not-accepted");
        assert!(wire::decode_request(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let mut large = bytes;
    large.extend(std::iter::repeat_n(b' ', RAW_LIMIT));
    assert!(wire::decode_request(&large).is_err());
}
#[test]
fn nullable_fields_and_acknowledgement_cannot_fabricate_cleanup_finality() {
    let mut r = row();
    r.validate().unwrap();
    let v = serde_json::to_value(&r).unwrap();
    for k in ["operationId", "reason"] {
        let mut missing = v.clone();
        missing.as_object_mut().unwrap().remove(k);
        assert!(serde_json::from_value::<Status>(missing).is_err());
    }
    r.effect = Effect::AcknowledgedUnconfirmed;
    assert!(r.validate().is_err());
    r.operation_id = Some("github-play-cleanup-1".into());
    r.state = State::Settled;
    r.settlement = Settlement::Settled;
    r.validate().unwrap();
    r.state = State::Unknown;
    r.settlement = Settlement::Unknown;
    r.reason = Some(Reason::CleanupUnknown);
    r.validate().unwrap();
    r.do_not_replay = false;
    assert!(r.validate().is_err());
    for v in [
        "github-play-cleanup-0",
        "github-play-cleanup-01",
        "github-play-cleanup-18446744073709551616",
        "github-actions-retry-1",
    ] {
        assert!(!operation_id(v));
    }
    assert!(operation_id("github-play-cleanup-18446744073709551615"));
}
#[test]
fn response_rematches_instance_and_fixed_small_bound() {
    let r = row();
    let mut response = wire::Response {
        version: 1,
        request_id: id('e'),
        service_instance: r.origin.service_instance.clone(),
        client_id: id('f'),
        session_id: id('a'),
        response: wire::ResponseBody::PlayCleanupRequest(r),
    };
    assert!(wire::encode_response(&response).unwrap().len() < STATUS_LIMIT);
    response.service_instance = id('c');
    assert!(wire::encode_response(&response).is_err());
    assert!(Access {
        purpose: Purpose::PlayCleanup,
        service_instance: id('b'),
        project_id: id('a'),
        consent_id: id('d'),
        enabled: false,
        remaining_ms: 0
    }
    .valid());
    assert!(!Access {
        purpose: Purpose::PlayCleanup,
        service_instance: id('b'),
        project_id: id('a'),
        consent_id: id('d'),
        enabled: true,
        remaining_ms: 0
    }
    .valid());
}

#[test]
fn typed_tag_wire_never_widens_old_default_or_accepts_free_provider_arguments() {
    let old=row().origin; let value=serde_json::to_value(&old).unwrap();
    assert!(value.get("purpose").is_none());
    assert_eq!(serde_json::from_value::<Query>(value.clone()).unwrap(), old);
    let mut tag=value.clone();tag["purpose"]=serde_json::json!("version-tag");
    let parsed:Query=serde_json::from_value(tag.clone()).unwrap();
    assert_eq!(parsed.purpose,Purpose::VersionTag);assert_ne!(parsed,old);
    for bad in [serde_json::Value::Null,serde_json::json!("push"),serde_json::json!({})] {
        tag["purpose"]=bad;assert!(serde_json::from_value::<Query>(tag.clone()).is_err());
    }
    for field in ["tag", "sha", "key", "confirmation"] {
        let mut bad=value.clone();bad[field]=serde_json::json!("not-accepted");
        assert!(serde_json::from_value::<Query>(bad).is_err());
    }
}
