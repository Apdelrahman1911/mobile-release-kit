//! Actual CLI parser/output helpers; no process, IPC, provider or filesystem.
use super::*;
use store::release::tests as data;

#[test]
fn store_release_cli_all_modes_report_only_exact_sanitized_original() {
    for (kind, platform, mode) in data::cases() {
        let r = data::review(kind, platform, mode);
        let q = store::Query {
            project_id: id(1),
            service_instance: id(2),
            request_id: id(5),
        };
        let response = p::Response {
            version: 1,
            request_id: id(6),
            service_instance: id(2),
            client_id: id(7),
            session_id: id(8),
            response: p::ResponseBody::StoreRequest(store::Status {
                origin: q.clone(),
                grant_id: id(3),
                review_id: id(4),
                revision: 8,
                review: r.clone(),
                state: store::State::Complete,
                settlement: p::Settlement::Settled,
                reason: store::Reason::None,
                operation: Some(store::Operation {
                    operation_id: r.operation_id.clone(),
                    owner_generation: r.owner_generation.clone(),
                    status_revision: 7,
                }),
                outcome: Some(store::Outcome::Complete),
                result: Some(data::report(&r)),
            }),
        };
        for json in [true, false] {
            let (code, bytes) = output(&response, &q, None, json).unwrap();
            assert_eq!(code, 0);
            assert!(bytes.len() <= store::STATUS_LIMIT);
            let text = String::from_utf8(bytes).unwrap();
            for private in [
                "authorizationId",
                "sourceCommit",
                "appStoreAppId",
                "applicationId",
                "credentialConfig",
                "store-submit",
            ] {
                assert!(!text.contains(private));
            }
        }
        let mut wrong = q;
        wrong.request_id = id(9);
        assert!(output(&response, &wrong, None, true).is_err());
    }
}

#[test]
fn store_release_cli_permission_metadata_does_not_add_material_or_mode_arguments() {
    let base = format!(
        "store-submit {} {} {} {} --reviewed",
        id(1).as_str(),
        id(2).as_str(),
        id(3).as_str(),
        id(4).as_str()
    );
    assert!(parse(&words(&base)).is_ok());
    for suffix in [
        " --execute",
        " --reconcile",
        " --mode production-submit",
        " --credential token",
        " --stage production",
        " --retry",
        " --force",
    ] {
        assert!(parse(&words(&(base.clone() + suffix))).is_err());
    }
    let q = store::Query {
        project_id: id(1),
        service_instance: id(2),
        request_id: id(5),
    };
    let text = String::from_utf8(unconfirmed(&q, Error::StateUnknown, true)).unwrap();
    assert!(text.contains("doNotReplay"));
    assert!(!text.contains("store-submit"));
}
