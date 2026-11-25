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
        runtime_project_id: "workflow-project".into(),
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
fn workflow_edit_wire_is_closed_required_null_and_never_an_arbitrary_editor() {
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
        request: wire::RequestBody::WorkflowEditPrepare(Prepare {
            origin: row.origin.clone(),
            expected_observation_revision: 7,
        }),
    };
    let bytes = wire::encode_request(&request).unwrap();
    assert!(bytes.len() < wire::REQUEST_BYTES);
    assert!(matches!(
        wire::decode_request(&bytes).unwrap().request,
        wire::RequestBody::WorkflowEditPrepare(_)
    ));
    let mut body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    body["request"]["params"]["draft"] = json!({});
    assert!(wire::decode_request(&serde_json::to_vec(&body).unwrap()).is_err());
}
#[test]
fn four_fixed_summaries_do_not_mint_a_preview_and_cross_instance_or_newline_refuse() {
    let review = Review {
        plan_token:id('5'),native_status_revision:12,draft_revision:7,baseline_generation:3,
        files:IDS.map(|id| File {id,action:FileAction::Create,observed:None,
            generated:Bytes{byte_length:15,sha256:"a".repeat(64)}}),
        created_directories:2,core_version:"0.3.0".into(),resource_version:1,resource_sha256:"b".repeat(64),
        tooling_repository:"example/toolkit".into(),tooling_sha:"b".repeat(40),
    };
    review.validate().unwrap();
    for mutate in 0..6 {
        let mut bad=review.clone();
        match mutate {
            0=>bad.files.swap(0,1),
            1=>bad.files[0].generated.sha256.push('\n'),
            2=>bad.files[0].generated.byte_length=16385,
            3=>bad.created_directories=3,
            4=>bad.tooling_repository="https://example/toolkit".into(),
            _=>bad.core_version.push('\n'),
        }
        assert!(bad.validate().is_err());
    }
    let mut update=review.clone(); update.created_directories=0;
    update.files[0].action=FileAction::Update;
    update.files[0].observed=Some(Bytes{byte_length:16,sha256:"b".repeat(64)});
    update.validate().unwrap();
    update.files[0].observed.as_mut().unwrap().sha256="a".repeat(64);
    assert!(update.validate().is_err());
    let mut preserve=review.clone(); preserve.created_directories=0;
    preserve.files[0].action=FileAction::Preserve;preserve.files[0].observed=Some(preserve.files[0].generated.clone());
    preserve.validate().unwrap();
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
        response: wire::ResponseBody::WorkflowEditRequest(row.clone()),
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
