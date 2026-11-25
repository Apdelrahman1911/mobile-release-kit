use super::*;
use crate::service_protocol as wire;
use serde_json::json;
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn queued() -> Status {
    Status {
        schema_version: 1,
        origin: Query {
            service_instance: id('1'),
            project_id: id('2'),
            request_id: id('3'),
        },
        runtime_project_id: "init-project".into(),
        revision: 1,
        phase: Phase::QueuedOpen,
        settlement: Settlement::Pending,
        original: None,
        review: None,
        permission_available: false,
        permission_consumed: false,
        remaining_ms: 30_000,
        cancel_requested: false,
        result: None,
        do_not_replay: true,
    }
}
#[test]
fn initialization_wire_is_closed_required_null_and_never_an_arbitrary_editor() {
    let row = queued();
    row.validate().unwrap();
    let value = serde_json::to_value(&row).unwrap();
    for field in ["original", "review", "result"] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Status>(missing).is_err());
    }
    for field in ["draft", "root", "force", "toolkit", "authorization"] {
        let mut extra = value.clone();
        extra[field] = json!("not authority");
        assert!(serde_json::from_value::<Status>(extra).is_err());
    }
    for edit in 0..5 {
        let mut bad = row.clone();
        match edit {
            0 => bad.permission_available = true,
            1 => bad.phase = Phase::Final,
            2 => bad.settlement = Settlement::Settled,
            3 => bad.do_not_replay = false,
            _ => bad.remaining_ms = 900_001,
        };
        assert!(bad.validate().is_err());
    }
    let request = wire::Request {
        version: wire::VERSION,
        request_id: id('4'),
        request: wire::RequestBody::InitializationPrepare(Prepare {
            origin: row.origin.clone(),
            expected_observation_revision: 7,
        }),
    };
    let bytes = wire::encode_request(&request).unwrap();
    assert!(bytes.len() < wire::REQUEST_BYTES);
    assert!(matches!(
        wire::decode_request(&bytes).unwrap().request,
        wire::RequestBody::InitializationPrepare(_)
    ));
    let mut body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    body["request"]["params"]["draft"] = json!({});
    assert!(wire::decode_request(&serde_json::to_vec(&body).unwrap()).is_err());
}
#[test]
fn compact_inventory_counts_do_not_mint_a_native_preview_or_cross_instance_response() {
    let review = Review {
        plan_token: id('5'),
        native_status_revision: 12,
        draft_revision: 7,
        baseline_generation: 3,
        file_count: 6,
        created_files: 6,
        preserved_files: 0,
        appended_files: 0,
        created_directories: 3,
        tooling_repository: "example/toolkit".into(),
        tooling_sha: "b".repeat(40),
    };
    review.validate().unwrap();
    let mut bad = review.clone();
    bad.appended_files = 1;
    assert!(bad.validate().is_err());
    bad = review.clone();
    bad.tooling_repository = "https://example/toolkit".into();
    assert!(bad.validate().is_err());
    let mut row = queued();
    row.phase = Phase::Reviewing;
    row.original = Some(Original {
        session_id: id('6'),
        owner_generation: id('7'),
        revision: id('8'),
    });
    row.review = Some(review);
    row.validate().unwrap();
    let mut response = wire::Response {
        version: wire::VERSION,
        request_id: id('9'),
        service_instance: id('1'),
        client_id: id('a'),
        session_id: id('b'),
        response: wire::ResponseBody::InitializationRequest(row.clone()),
    };
    let bytes = wire::encode_response(&response).unwrap();
    assert!(bytes.len() < STATUS_BYTES);
    assert!(
        wire::decode_response(&bytes, &response.request_id, &response.service_instance).is_ok()
    );
    response.service_instance = id('f');
    assert!(wire::encode_response(&response).is_err());
    let allow = Allow {
        origin: row.origin,
        original: row.original.unwrap(),
        plan_token: id('5'),
        expected_native_status_revision: 12,
        expected_request_revision: 9,
        consent_version: CONSENT.into(),
    };
    allow.validate().unwrap();
    for revision in [0, u32::MAX] {
        let mut bad = allow.clone();
        bad.expected_request_revision = revision;
        assert!(bad.validate().is_err());
    }
    let mut bad = allow;
    bad.consent_version = crate::service_configuration_protocol::CONSENT.into();
    assert!(bad.validate().is_err());
}
