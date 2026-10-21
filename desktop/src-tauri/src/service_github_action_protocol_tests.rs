use super::*;
fn id() -> Id {
    Id::parse(&"a".repeat(32)).unwrap()
}
fn status(kind: Kind) -> Status {
    Status {
        origin: Query {
            project_id: id(),
            service_instance: id(),
            request_id: id(),
        },
        grant_id: id(),
        review: Review {
            kind,
            session_id: "github-connection-1".into(),
            consent_id: "b".repeat(32),
            expected_revision: 1,
            prepared_sha256: "c".repeat(64),
        },
        revision: 1,
        state: State::Queued,
        settlement: Settlement::Pending,
        operation_id: None,
        reason: Reason::None,
        effect: Effect::NotSent,
        never_admitted: false,
        do_not_replay: true,
    }
}
#[test]
fn exact_three_kinds_and_original_operation_ids_do_not_upgrade_another_grant() {
    let kinds = [
        Kind::RepositoryCreate,
        Kind::DraftPrCreate,
        Kind::FailedJobsRetry,
    ];
    for kind in kinds {
        assert!(status(kind).validate().is_ok());
        assert!(kind.operation(&format!("{}1", kind.prefix())));
        for bad in ["0", "01", "-1", "18446744073709551616"] {
            assert!(!kind.operation(&format!("{}{bad}", kind.prefix())));
        }
        for other in kinds {
            if kind != other {
                assert_ne!(kind.consent(), other.consent());
                assert!(!kind.operation(&format!("{}1", other.prefix())));
            }
        }
    }
    assert!(serde_json::from_str::<Kind>("\"workflow-dispatch\"").is_err());
}
#[test]
fn strict_request_framing_refuses_private_fields_and_omitted_required_nulls() {
    let request = crate::service_protocol::Request {
        version: 1,
        request_id: id(),
        request: crate::service_protocol::RequestBody::GitHubActionSubmit(Submit {
            origin: status(Kind::RepositoryCreate).origin,
            grant_id: id(),
        }),
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    assert!(crate::service_protocol::decode_request(&bytes).is_ok());
    // Test the exact inner grammar independently of the tagged envelope layout.
    let mut inner = serde_json::to_value(Submit {
        origin: status(Kind::RepositoryCreate).origin,
        grant_id: id(),
    })
    .unwrap();
    inner["url"] = serde_json::json!("https://example.invalid");
    assert!(serde_json::from_value::<Submit>(inner).is_err());
    let mut row = serde_json::to_value(status(Kind::RepositoryCreate)).unwrap();
    row.as_object_mut().unwrap().remove("operationId");
    assert!(serde_json::from_value::<Status>(row).is_err());
    let mut large = bytes.clone();
    large.extend(std::iter::repeat_n(b' ', RAW_LIMIT + 1));
    assert!(crate::service_protocol::decode_request(&large).is_err());
}
#[test]
fn effect_and_never_admitted_are_not_interchangeable_with_native_success() {
    let mut s = status(Kind::RepositoryCreate);
    s.state = State::Complete;
    s.settlement = Settlement::Settled;
    assert!(s.validate().is_err());
    s.operation_id = Some("repository-create-1".into());
    s.effect = Effect::Accepted;
    assert!(s.validate().is_err());
    s.effect = Effect::CreatedObserved;
    assert!(s.validate().is_ok());
    s.never_admitted = true;
    assert!(s.validate().is_err());
    s.operation_id = None;
    s.effect = Effect::NotSent;
    s.state = State::Refused;
    s.reason = Reason::NativeRefused;
    assert!(s.validate().is_ok());
    s.do_not_replay = false;
    assert!(s.validate().is_err());
}
#[test]
fn all_closed_metadata_fits_status_with_wrapper_and_never_contains_material() {
    let mut s = status(Kind::FailedJobsRetry);
    s.review.session_id = "x".repeat(64);
    s.review.expected_revision = u32::MAX - 1;
    s.revision = u32::MAX - 1;
    s.operation_id = Some("github-actions-retry-18446744073709551615".into());
    s.effect = Effect::AcceptedUnconfirmed;
    s.state = State::Finishing;
    assert!(s.validate().is_ok());
    let response = crate::service_protocol::Response {
        version: 1,
        request_id: id(),
        service_instance: id(),
        client_id: id(),
        session_id: id(),
        response: crate::service_protocol::ResponseBody::GitHubActionRequest(s),
    };
    assert!(
        crate::service_protocol::encode_response(&response)
            .unwrap()
            .len()
            < STATUS_LIMIT
    );
    assert!(Access::empty().validate().is_ok());
}
