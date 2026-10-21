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
        review: Review::from_prepared(kind, PreparedReference {
            session_id: "github-connection-1".into(),
            consent_id: "b".repeat(32),
            expected_revision: 1,
            prepared_sha256: "c".repeat(64),
        }).unwrap(),
        revision: 1,
        state: State::Queued,
        settlement: Settlement::Pending,
        operation_id: None,
        reason: Reason::None,
        effect: Effect::NotSent,
        never_admitted: false,
        do_not_replay: true, snapshot: None,
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
    s.review.prepared_mut().unwrap().session_id = "x".repeat(64);
    s.review.prepared_mut().unwrap().expected_revision = u32::MAX - 1;
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

#[test]
fn publication_references_are_disjoint_typed_payloads_and_preserve_original_three_bytes() {
    for kind in [Kind::RepositoryCreate, Kind::DraftPrCreate, Kind::FailedJobsRetry] {
        let s=status(kind);
        let expected=serde_json::json!({"kind":kind,"sessionId":"github-connection-1","consentId":"b".repeat(32),"expectedRevision":1,"preparedSha256":"c".repeat(64)});
        assert_eq!(serde_json::to_value(&s.review).unwrap(),expected);
        assert_eq!(serde_json::from_value::<Review>(expected).unwrap(),s.review);
    }
    for kind in [Kind::SetupPublish, Kind::SetupReconcile] {
        let mut value=serde_json::json!({"kind":kind,"sessionId":"github-connection-1","expectedRevision":1});
        let (id,hash,foreign)=if kind==Kind::SetupPublish { ("consentId","preparedSha256","marker") } else { ("marker","recordSha256","consentId") };
        value[id]=serde_json::json!("a".repeat(32));
        let selected:Selection=serde_json::from_value(value.clone()).unwrap(); assert!(selected.valid());
        value[hash]=serde_json::json!("b".repeat(64));
        let review:Review=serde_json::from_value(value.clone()).unwrap(); assert!(review.valid()); assert_eq!(review.kind(),kind);
        let mut bad=value.clone();bad[foreign]=serde_json::json!("c".repeat(32));assert!(serde_json::from_value::<Review>(bad).is_err());
        let mut bad=value.clone();bad[id]=serde_json::Value::Null;assert!(serde_json::from_value::<Review>(bad).is_err());
        let mut bad=value.clone();bad["purpose"]=serde_json::json!("counter");assert!(serde_json::from_value::<Review>(bad).is_err());
        let mut bad=value.clone();bad["kind"]=serde_json::json!("counter-publish");assert!(serde_json::from_value::<Review>(bad).is_err());
        let encoded=serde_json::to_vec(&review).unwrap();assert!(encoded.len()<512);
        assert!(!Effect::CreatedObserved.valid_for(kind)); assert!(!Effect::Accepted.valid_for(kind));
    }
    assert!(Effect::None.valid_for(Kind::SetupReconcile));
    assert!(!Effect::NotSent.valid_for(Kind::SetupReconcile));
    assert!(!Effect::PotentiallyApplied.valid_for(Kind::SetupReconcile));
    assert!(Effect::BranchObserved.valid_for(Kind::SetupReconcile));
    assert!(!Effect::None.valid_for(Kind::SetupPublish));
}
