//! Pure transport DATA. These do not create a native approval or join proof.
use super::*;
use serde_json::{json, Value};
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn review(kind: Kind) -> Review {
    Review {
        kind,
        platform: Platform::Android,
        draft_revision: 1,
        baseline_generation: 2,
        prepared: kind.saved().then(|| Prepared {
            operation_id: id('a'),
            owner_generation: id('b'),
            status_revision: 3,
        }),
        sources: kind.sources().then(|| Sources {
            registration_generation: 4,
            source_generation: 6,
            review_id: (kind == Kind::RegisterReviewedSources).then(|| id('c')),
        }),
        acquisition: None,
    }
}
#[test]
fn five_closed_reviews_require_exact_pairs_and_no_extra_fields() {
    for k in [
        Kind::Doctor,
        Kind::InspectRequirements,
        Kind::AcquireMissing,
        Kind::InspectPickedSources,
        Kind::RegisterReviewedSources,
    ] {
        let r = review(k);
        assert!(r.valid());
        let mut v = serde_json::to_value(&r).unwrap();
        assert_eq!(serde_json::from_value::<Review>(v.clone()).unwrap(), r);
        v["authority"] = json!(true);
        assert!(serde_json::from_value::<Review>(v).is_err());
        for field in ["prepared", "sources"] {
            let mut v = serde_json::to_value(&r).unwrap();
            v.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Review>(v).is_err());
        }
        let mut bad = r.clone();
        bad.platform = Platform::Ios;
        assert_eq!(bad.valid(), k == Kind::Doctor);
        let mut bad = r;
        bad.prepared = Some(Prepared {
            operation_id: id('a'),
            owner_generation: id('b'),
            status_revision: 0,
        });
        assert!(!bad.valid());
    }
    let mut r = review(Kind::RegisterReviewedSources);
    r.sources.as_mut().unwrap().review_id = None;
    assert!(!r.valid());
    assert!(serde_json::from_value::<Kind>(json!("download-any-url")).is_err());
}
#[test]
fn summaries_do_not_upgrade_completion_or_foreign_original() {
    let r = review(Kind::Doctor);
    let q = Query {
        project_id: id('1'),
        service_instance: id('2'),
        request_id: id('3'),
    };
    let mut s = Status {
        origin: q,
        grant_id: id('4'),
        review_id: id('5'),
        revision: 1,
        review: r,
        state: State::Complete,
        settlement: Settlement::Settled,
        reason: Reason::None,
        operation: Some(Operation {
            operation_id: id('a'),
            owner_generation: Some(id('b')),
            registration_generation: None,
        }),
        outcome: Some(Outcome::Complete),
        result: Some(Report::Doctor {
            checks: vec![Finding {
                check: Check::Git,
                status: CheckStatus::Failed,
            }],
        }),
    };
    assert!(s.validate().is_ok()); // finished check != successful Git/tool readiness
    s.settlement = Settlement::Pending;
    assert!(s.validate().is_err());
    s.settlement = Settlement::Settled;
    s.result = Some(Report::AcquireMissing {
        staged: vec![Component::Jdk],
    });
    assert!(s.validate().is_err());
    s.state = State::Unknown;
    s.settlement = Settlement::Unknown;
    s.outcome = Some(Outcome::Unknown);
    s.reason = Reason::CleanupUnknown;
    s.result = None;
    assert!(s.validate().is_ok());
    s.result = Some(Report::Doctor { checks: vec![] });
    assert!(s.validate().is_err());
    let r = review(Kind::AcquireMissing);
    let mut o = Operation {
        operation_id: id('a'),
        owner_generation: Some(id('b')),
        registration_generation: None,
    };
    assert!(o.valid_for(&r));
    o.operation_id = id('c');
    assert!(!o.valid_for(&r));
    let r = review(Kind::InspectPickedSources);
    let mut o = Operation {
        operation_id: id('a'),
        owner_generation: None,
        registration_generation: Some(5),
    };
    assert!(o.valid_for(&r));
    o.registration_generation = Some(4);
    assert!(!o.valid_for(&r));
}
#[test]
fn exact_struct_report_and_global_frame_bounds() {
    for v in [
        json!({"kind":"doctor","checks":[],"path":"/not-allowed"}),
        json!({"kind":"acquire-missing","staged":["jdk","jdk"]}),
    ] {
        if let Ok(r) = serde_json::from_value::<Report>(v) {
            assert!(!r.valid_for(&review(Kind::AcquireMissing)));
        }
    }
    let request = crate::service_protocol::Request {
        version: 1,
        request_id: id('a'),
        request: crate::service_protocol::RequestBody::ToolSetupSubmit(Submit {
            origin: Query {
                project_id: id('1'),
                service_instance: id('2'),
                request_id: id('3'),
            },
            grant_id: id('4'),
            review_id: id('5'),
        }),
    };
    let bytes = crate::service_protocol::encode_request(&request).unwrap();
    assert!(bytes.len() < RAW_LIMIT);
    let mut raw: Value = serde_json::from_slice(&bytes).unwrap();
    raw["request"]["draft"] = json!({});
    assert!(serde_json::from_value::<crate::service_protocol::Request>(raw).is_err());
    assert_eq!((RAW_LIMIT, STATUS_LIMIT, REPORT_LIMIT), (1024, 8192, 4096));
    assert_eq!(
        Kind::AcquireMissing.action(),
        crate::service_protocol::Action::PrepareTools
    );
    assert!(Access::empty().validate().is_ok());
    let mut a = Access::empty();
    a.enabled = true;
    assert!(a.validate().is_err());
}

fn reviewed_acquisition() -> Review {
    serde_json::from_value(json!({"kind":"acquire-reviewed-missing","platform":"android","draftRevision":1,"baselineGeneration":2,
        "prepared":null,"sources":null,"acquisition":{"operationId":id('a'),"ownerGeneration":id('b'),"requirementsSha256":"c".repeat(64),
        "missing":["android-build-tools"],"compatible":["jdk","android-platform","gradle"]}})).unwrap()
}
#[test]
fn reviewed_acquire_is_omitted_for_old_six_and_requires_exact_non_null_partition() {
    let r = reviewed_acquisition();
    assert!(r.valid());
    assert_eq!(r.kind.action(), crate::service_protocol::Action::PrepareTools);
    let data = serde_json::to_value(&r).unwrap();
    for kind in [Kind::Doctor,Kind::InspectRequirements,Kind::AcquireMissing,Kind::InspectPickedSources,Kind::RegisterReviewedSources,Kind::InspectSavedRequirements] {
        let mut old = review(kind);
        if kind == Kind::InspectSavedRequirements { old.prepared = None; }
        assert!(old.valid());
        let encoded = serde_json::to_value(&old).unwrap();
        assert_eq!(encoded.as_object().unwrap().len(), 6);
        assert!(encoded.get("acquisition").is_none());
        assert_eq!(serde_json::to_vec(&serde_json::from_value::<Review>(encoded.clone()).unwrap()).unwrap(), serde_json::to_vec(&old).unwrap());
        let mut null = encoded.clone(); null["acquisition"] = Value::Null;
        assert!(serde_json::from_value::<Review>(null).is_err());
        let mut cross = encoded; cross["acquisition"] = data["acquisition"].clone();
        assert!(!serde_json::from_value::<Review>(cross).unwrap().valid());
        assert_ne!(kind.consent(),r.kind.consent());
    }
    for field in ["prepared","sources","acquisition"] {
        let mut missing = data.clone(); missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Review>(missing).map_or(true, |r| !r.valid()));
    }
    for (field,value) in [("missing",json!([])),("compatible",json!(["jdk","gradle","android-platform"])),
        ("missing",json!(["sdk-build-tools"])),("missing",json!(["jdk"])),("requirementsSha256",json!("c".repeat(64)+"\n"))] {
        let mut bad = data.clone(); bad["acquisition"][field] = value;
        assert!(serde_json::from_value::<Review>(bad).map_or(true, |r| !r.valid()));
    }
    let mut extra = data; extra["acquisition"]["path"] = json!("/not-a-source");
    assert!(serde_json::from_value::<Review>(extra).is_err());
}
#[test]
fn reviewed_acquisition_status_has_a_new_identity_and_exact_staged_partition_with_bounded_heap() {
    let r = reviewed_acquisition();
    // Use the actual outer streaming decoder, not from_value's exact-length
    // array hint. Every supported native partition must fit after the wire.
    let all = [Component::Jdk, Component::AndroidPlatform, Component::AndroidBuildTools, Component::Gradle];
    for mask in 1u8..16 {
        let mut current = r.clone();
        let acquisition = current.acquisition.as_mut().unwrap();
        acquisition.missing = Vec::with_capacity(4);
        acquisition.compatible = Vec::with_capacity(4);
        for (index, component) in all.into_iter().enumerate() {
            if mask & (1 << index) != 0 { acquisition.missing.push(component); }
            else { acquisition.compatible.push(component); }
        }
        let staged = acquisition.missing.clone();
        let response = crate::service_protocol::Response {
            version: crate::service_protocol::VERSION, request_id: id('8'), service_instance: id('2'),
            client_id: id('9'), session_id: id('f'),
            response: crate::service_protocol::ResponseBody::ToolSetupRequest(Status {
                origin: Query { project_id: id('1'), service_instance: id('2'), request_id: id('3') },
                grant_id: id('4'), review_id: id('5'), revision: 1, review: current,
                state: State::Complete, settlement: Settlement::Settled, reason: Reason::None,
                operation: Some(Operation { operation_id: id('d'), owner_generation: Some(id('e')), registration_generation: None }),
                outcome: Some(Outcome::Complete), result: Some(Report::AcquireReviewedMissing { staged }),
            }),
        };
        let bytes = crate::service_protocol::encode_response(&response).unwrap();
        let decoded = crate::service_protocol::decode_response(&bytes, &id('8'), &id('2')).unwrap();
        assert_eq!(decoded, response);
        let crate::service_protocol::ResponseBody::ToolSetupRequest(row) = decoded.response else { panic!("wrong response kind") };
        let acquisition = row.review.acquisition.as_ref().unwrap();
        assert!(acquisition.missing.capacity() <= 4 && acquisition.compatible.capacity() <= 4);
        assert!(acquisition.retained_bytes().unwrap() <= ACQUISITION_HEAP_BYTES);
        for field in ["missing", "compatible"] {
            let mut extra: Value = serde_json::from_slice(&bytes).unwrap();
            extra["response"]["value"]["review"]["acquisition"][field] = json!(["jdk", "android-platform", "android-build-tools", "gradle", "jdk"]);
            assert!(crate::service_protocol::decode_response(&serde_json::to_vec(&extra).unwrap(), &id('8'), &id('2')).is_err());
        }
    }
    let mut op = Operation { operation_id:id('d'),owner_generation:Some(id('e')),registration_generation:None };
    assert!(op.valid_for(&r));
    op.operation_id = id('a'); assert!(!op.valid_for(&r));
    op.operation_id = id('d'); op.owner_generation = Some(id('b')); assert!(!op.valid_for(&r));
    assert!(Report::AcquireReviewedMissing { staged:vec![Component::AndroidBuildTools] }.valid_for(&r));
    for report in [Report::AcquireMissing { staged:vec![Component::AndroidBuildTools] },
        Report::AcquireReviewedMissing { staged:vec![Component::Jdk] },
        Report::InspectSavedRequirements { missing:vec![Component::AndroidBuildTools] }] { assert!(!report.valid_for(&r)); }
    let a = r.acquisition.as_ref().unwrap();
    assert!(a.retained_bytes().unwrap() <= ACQUISITION_HEAP_BYTES);
    let mut expanded = r.clone(); expanded.acquisition.as_mut().unwrap().missing.reserve_exact(8);
    assert!(!expanded.valid());
    let mut expanded = r; expanded.acquisition.as_mut().unwrap().requirements_sha256.reserve_exact(256);
    assert!(!expanded.valid()); // Capacity, not only serialized length, is charged.
    assert_eq!((REQUEST_LIMIT,RAW_LIMIT,STATUS_LIMIT,REPORT_LIMIT),(32,1024,8192,4096));
}
