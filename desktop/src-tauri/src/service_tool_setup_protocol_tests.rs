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
