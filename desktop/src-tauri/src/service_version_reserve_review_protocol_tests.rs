use super::*;
use serde_json::json;
fn id(n: u8) -> crate::service_protocol::Id {
    crate::service_protocol::Id::parse(&format!("{n:032x}")).unwrap()
}
fn input() -> Request {
    Request {
        origin: Query {
            project_id: id(1),
            service_instance: id(2),
            request_id: id(3),
        },
        options: Options {
            reference: "refs/heads/main".into(),
            increment: Increment::Build,
            new_candidate: false,
            acknowledge_limitations: true,
            future_tag: None,
        },
    }
}
#[test]
fn review_options_are_closed_and_never_select_source_store_or_authority() {
    let input = input();
    input.validate().unwrap();
    for increment in [
        Increment::Build,
        Increment::Patch,
        Increment::Minor,
        Increment::Major,
    ] {
        let mut valid = input.clone();
        valid.options.increment = increment;
        valid.options.future_tag = Some("refs/tags/v2.0.0".into());
        valid.validate().unwrap();
        assert_eq!(
            serde_json::from_slice::<Request>(&serde_json::to_vec(&valid).unwrap()).unwrap(),
            valid
        );
    }
    let value = serde_json::to_value(&input).unwrap();
    for field in [
        "source",
        "floor",
        "platform",
        "candidate",
        "token",
        "deadline",
        "path",
    ] {
        let mut v = value.clone();
        v["options"][field] = json!("not-authority");
        assert!(serde_json::from_value::<Request>(v).is_err());
    }
    for reference in [
        "refs/tags/v1",
        "refs/heads/a.lock",
        "refs/heads/a/../b",
        "refs/heads/main\n",
    ] {
        let mut v = input.clone();
        v.options.reference = reference.into();
        assert!(v.validate().is_err())
    }
    let mut null = value;
    null["options"]["futureTag"] = json!(null);
    assert!(serde_json::from_value::<Request>(null).is_err());
    assert!(serde_json::from_str::<Options>(r#"{"reference":"refs/heads/a","reference":"refs/heads/b","increment":"build","newCandidate":false,"acknowledgeLimitations":true}"#).is_err());
}
#[test]
fn actual_service_review_envelope_and_required_null_status_are_bounded() {
    use crate::service_protocol as s;
    let input = input();
    let request = s::Request {
        version: s::VERSION,
        request_id: id(4),
        request: s::RequestBody::VersionReserveReview(input.clone()),
    };
    let bytes = s::encode_request(&request).unwrap();
    assert!(matches!(
        s::decode_request(&bytes).unwrap().request,
        s::RequestBody::VersionReserveReview(_)
    ));
    let mut over = bytes.clone();
    over.extend(std::iter::repeat_n(b' ', REQUEST_BYTES + 1 - bytes.len()));
    assert!(s::decode_request(&over).is_err());
    let status = Status {
        schema_version: 1,
        origin: input.origin,
        runtime_project_id: "project-1".into(),
        options: input.options,
        revision: 1,
        phase: Phase::Queued,
        settlement: Settlement::Pending,
        operation_id: None,
        review: None,
        remaining_ms: 0,
        reason: None,
        do_not_replay: true,
    };
    status.validate().unwrap();
    let mut v = serde_json::to_value(&status).unwrap();
    v.as_object_mut().unwrap().remove("review");
    assert!(serde_json::from_value::<Status>(v).is_err());
    let mut wrong = status;
    wrong.phase = Phase::ReviewReady;
    assert!(wrong.validate().is_err());
}
