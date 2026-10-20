use super::*;
use serde_json::json;
fn id(n: u8) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
#[test]
fn access_requires_every_nullable_field_and_exact_dependency_shapes() {
    let empty = serde_json::to_value(Access::empty()).unwrap();
    for name in [
        "serviceInstance",
        "projectId",
        "grantId",
        "reviewId",
        "reviewRevision",
        "requestId",
        "completedOperationId",
    ] {
        let mut bad = empty.clone();
        bad.as_object_mut().unwrap().remove(name);
        assert!(serde_json::from_value::<Access>(bad).is_err(), "{name}");
    }
    let grant = Access {
        service_instance: Some(id(1)),
        project_id: Some(id(2)),
        grant_id: Some(id(3)),
        review_id: Some(id(4)),
        review_revision: Some(1),
        enabled: true,
        remaining_ms: 1000,
        consumed: false,
        request_id: None,
        completed_operation_id: None,
    };
    grant.validate().unwrap();
    for (field, value) in [
        ("remainingMs", json!(0)),
        ("remainingMs", json!(120001)),
        ("enabled", json!(false)),
        ("reviewRevision", json!(0)),
        ("reviewRevision", json!(u32::MAX)),
        ("requestId", json!(id(6))),
        ("completedOperationId", json!(id(7))),
        ("projectId", json!(null)),
    ] {
        let mut bad = serde_json::to_value(&grant).unwrap();
        bad[field] = value;
        assert!(
            serde_json::from_value::<Access>(bad)
                .unwrap()
                .validate()
                .is_err(),
            "{field}"
        );
    }
    let mut returned = grant;
    returned.enabled = false;
    returned.remaining_ms = 0;
    returned.consumed = true;
    returned.request_id = Some(id(6));
    returned.completed_operation_id = Some(id(7));
    returned.validate().unwrap();
}
#[test]
fn request_and_status_closed_typed_nulls_do_not_permit_authority_fields() {
    let q = Query {
        project_id: id(1),
        service_instance: id(2),
        request_id: id(3),
    };
    let input = Submit {
        origin: q.clone(),
        grant_id: id(4),
        review_id: id(5),
    };
    let mut bad = serde_json::to_value(input).unwrap();
    bad["source"] = json!("not accepted");
    assert!(serde_json::from_value::<Submit>(bad).is_err());
    let row = Status {
        origin: q,
        grant_id: id(4),
        review_id: id(5),
        revision: 1,
        state: State::Queued,
        operation_id: None,
        settlement: Settlement::Pending,
        reason: None,
        reservation: None,
        do_not_replay: true,
    };
    row.validate().unwrap();
    for field in ["operationId", "reason", "reservation"] {
        let mut bad = serde_json::to_value(&row).unwrap();
        bad.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Status>(bad).is_err());
        let mut bad = serde_json::to_value(&row).unwrap();
        bad[field] = json!(42);
        assert!(serde_json::from_value::<Status>(bad).is_err());
    }
    let mut wrong = row.clone();
    wrong.state = State::Reserved;
    assert!(wrong.validate().is_err());
    wrong = row.clone();
    wrong.settlement = Settlement::Settled;
    assert!(wrong.validate().is_err());
    wrong = row;
    wrong.state = State::Unknown;
    wrong.settlement = Settlement::Unknown;
    assert!(wrong.validate().is_err());
    wrong.reason = Some(Reason::CleanupUnknown);
    wrong.validate().unwrap();
}
#[test]
fn reserve_transport_uses_existing_closed_envelope_and_bounded_final_snapshot() {
    use crate::service_protocol as s;
    let query = Query {
        project_id: id(1),
        service_instance: id(2),
        request_id: id(3),
    };
    for body in [
        s::RequestBody::VersionReserveSubmit(Submit {
            origin: query.clone(),
            grant_id: id(4),
            review_id: id(5),
        }),
        s::RequestBody::VersionReserveStatus(query.clone()),
        s::RequestBody::VersionReserveCancel(query.clone()),
    ] {
        let request = s::Request {
            version: s::VERSION,
            request_id: id(6),
            request: body,
        };
        let bytes = s::encode_request(&request).unwrap();
        assert!(bytes.len() < RAW_LIMIT);
        assert_eq!(s::decode_request(&bytes).unwrap(), request);
        let mut oversized = vec![b' '; RAW_LIMIT];
        oversized.extend(&bytes);
        assert!(s::decode_request(&oversized).is_err());
    }
    let row = Status {
        origin: query,
        grant_id: id(4),
        review_id: id(5),
        revision: 2,
        state: State::Reserved,
        operation_id: Some(id(7)),
        settlement: Settlement::Settled,
        reason: None,
        reservation: Some(Reservation {
            candidate_id: "12345678-1234-4234-9234-123456789abc".into(),
            name: "1.2.3".into(),
            build: 9,
        }),
        do_not_replay: true,
    };
    let response = s::Response {
        version: s::VERSION,
        request_id: id(6),
        service_instance: id(2),
        client_id: id(10),
        session_id: id(11),
        response: s::ResponseBody::VersionReserveRequest(row),
    };
    assert!(s::encode_response(&response).unwrap().len() < STATUS_LIMIT);
    let mut wrong = response;
    wrong.service_instance = id(9);
    assert!(s::encode_response(&wrong).is_err());
}
